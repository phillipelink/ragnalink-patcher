//! A telinha do RagnaShield — card branco moderno com o emblema e uma barra de
//! progresso animada, na inicialização.
//!
//! # Princípio de segurança: a telinha NUNCA atrapalha a proteção
//!
//! Ela roda numa **thread própria**, com o próprio laço de mensagens. O fluxo
//! principal do Loader (sessão → ticket → injeção → handshake → resume) segue
//! independente: se a criação da janela falhar, se o logo não pintar, se
//! qualquer coisa der errado aqui, o jogo abre do mesmo jeito. Cosmético não
//! pode ter poder de vida e morte sobre funcional.
//!
//! # Como o "loading" funciona
//!
//! A janela é **em camadas** (`WS_EX_LAYERED` + `UpdateLayeredWindow`): o Windows
//! compõe a imagem sobre a tela pelo canal alfa por pixel — é o que dá os cantos
//! arredondados e a sombra suave do card, sem retângulo.
//!
//! A **base** (card branco + medalhão + trilha vazia) vem pronta no `.bin`,
//! premultiplicada. A cada quadro a thread copia a base, desenha o segmento azul
//! deslizando dentro da trilha, e chama `UpdateLayeredWindow` de novo. Não é gif:
//! é a janela sendo repintada ~50×/s enquanto o Loader trabalha por baixo.
//!
//! O segmento é desenhado **misturado sobre a trilha**, mantendo o alfa em 255 —
//! ou seja, ele nunca fura o card (nada de buraco transparente na barra).

#![cfg(windows)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::{HWND, POINT, SIZE};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::wingdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, SelectObject, AC_SRC_ALPHA,
    AC_SRC_OVER, BITMAPINFO, BITMAPINFOHEADER, BLENDFUNCTION, BI_RGB, DIB_RGB_COLORS,
};
use winapi::um::winuser::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetDC, GetSystemMetrics, PeekMessageW,
    PostMessageW, PostQuitMessage, RegisterClassW, ReleaseDC, TranslateMessage, UpdateLayeredWindow,
    MSG, PM_REMOVE, SM_CXSCREEN, SM_CYSCREEN, ULW_ALPHA, WM_CLOSE, WM_DESTROY, WM_QUIT, WNDCLASSW,
    WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};

/// A base do card, BGRA premultiplicada top-down, gerada no build a partir do
/// PNG do logo. Card branco arredondado + sombra + medalhão + trilha VAZIA.
static BASE_BGRA: &[u8] = include_bytes!("splash_bgra.bin");

// Dimensões da janela (= card + margem da sombra). Têm que bater com o `.bin`.
const LARGURA: i32 = 352;
const ALTURA: i32 = 371;

// A trilha da barra, em coordenadas da JANELA — batem com o que o build desenhou.
const TRACK_X0: usize = 70;
const TRACK_X1: usize = 282;
const TRACK_Y: usize = 320;
const TRACK_H: usize = 5;

// O segmento azul que desliza.
const SEG_W: f32 = 66.0; // largura do segmento
const FADE: f32 = 10.0; // suavização das pontas (efeito "cometa")
const AZUL_B: f32 = 235.0; // cor do segmento em BGR (RGB 51,130,235)
const AZUL_G: f32 = 130.0;
const AZUL_R: f32 = 51.0;

// Ritmo da animação.
const QUADRO_MS: u64 = 20; // ~50 quadros/s
const MEIA_VARREDURA_QUADROS: u32 = 45; // ~0,9 s de ponta a ponta

/// Quanto tempo, no mínimo, o card fica na tela — a sensação de "processando".
/// Numa máquina rápida a sessão, o ticket e a injeção passam num piscar; este
/// piso segura o card (com a barra rodando) mesmo assim. É o único número a
/// mexer se quiser a telinha mais longa ou mais curta.
const DURACAO_MINIMA_NA_TELA: std::time::Duration = std::time::Duration::from_millis(3000);

/// Respiro pós-retomada: o instante em que o cliente ainda está pintando a
/// própria janela. Como a telinha é TOPMOST, ela tapa esse flash; fechá-la cedo
/// demais deixaria escapar um quadro preto.
const RESPIRO_APOS_RETOMAR: std::time::Duration = std::time::Duration::from_millis(800);

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Alça da telinha: guarda a HWND para poder fechar, e a thread para dar join.
pub struct Splash {
    hwnd: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
    mostrado_em: std::time::Instant,
}

impl Splash {
    /// Sobe a telinha numa thread própria. Nunca falha de forma a atrapalhar o
    /// chamador — na pior das hipóteses, a janela simplesmente não aparece.
    pub fn mostrar() -> Splash {
        let hwnd = Arc::new(AtomicUsize::new(0));
        let hwnd_thread = hwnd.clone();
        let thread = std::thread::spawn(move || {
            rodar_janela(hwnd_thread);
        });
        Splash {
            hwnd,
            thread: Some(thread),
            mostrado_em: std::time::Instant::now(),
        }
    }

    /// Fecha a telinha. Chamada logo após o jogo ser retomado.
    ///
    /// Antes de fechar, garante o "respiro" do card — mas sem NUNCA segurar a
    /// proteção: quando isto roda, o jogo já foi retomado e a DLL já está de pé.
    /// O que espera aqui é só o pixel na tela.
    pub fn fechar(mut self) {
        let h = self.hwnd.load(Ordering::SeqCst);

        // Se a janela nunca subiu (falhou ao criar), não há o que esperar nem
        // fechar: cosmético que falhou não pode custar UM milissegundo ao jogador.
        if h == 0 {
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            return;
        }

        // Dois pisos, o maior vence:
        //  - DURACAO_MINIMA_NA_TELA segura o card por um tempo decente mesmo em
        //    máquina rápida (a barra rodando dá a sensação de "processando").
        //  - RESPIRO_APOS_RETOMAR cobre o cliente ainda pintando a própria janela,
        //    evitando um flash preto quando o pipeline foi lento e já passou do piso.
        let passado = self.mostrado_em.elapsed();
        let falta_total = DURACAO_MINIMA_NA_TELA.saturating_sub(passado);
        let espera = falta_total.max(RESPIRO_APOS_RETOMAR);
        std::thread::sleep(espera);

        // SAFETY: h é uma HWND válida criada pela thread da telinha; postar
        // WM_CLOSE é seguro de qualquer thread.
        unsafe { PostMessageW(h as HWND, WM_CLOSE, 0, 0) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Desenha o segmento azul deslizante dentro da trilha, sobre a base.
///
/// Sempre parte da base (que restaura a trilha do quadro anterior) e mistura o
/// azul por cima mantendo alfa 255 — a barra nunca fura o card.
fn desenhar_barra(bits: &mut [u8], n: u32) {
    // posição do segmento: vaivém suave (onda triangular) de ponta a ponta.
    let periodo = 2 * MEIA_VARREDURA_QUADROS;
    let fase = (n % periodo) as f32;
    let meia = MEIA_VARREDURA_QUADROS as f32;
    let t = if fase < meia {
        fase / meia // 0 -> 1
    } else {
        2.0 - fase / meia // 1 -> 0
    };
    let span = (TRACK_X1 - TRACK_X0) as f32 - SEG_W;
    let pos = TRACK_X0 as f32 + span * t; // borda esquerda do segmento
    let larg = LARGURA as usize;

    for dy in 0..TRACK_H {
        let y = TRACK_Y + dy;
        for x in TRACK_X0..TRACK_X1 {
            let idx = (y * larg + x) * 4;
            let b0 = BASE_BGRA[idx] as f32;
            let g0 = BASE_BGRA[idx + 1] as f32;
            let r0 = BASE_BGRA[idx + 2] as f32;

            let xf = x as f32;
            let a = if xf < pos || xf >= pos + SEG_W {
                0.0
            } else {
                let dl = xf - pos;
                let dr = (pos + SEG_W - 1.0) - xf;
                let borda = if dl < dr { dl } else { dr };
                (borda / FADE).min(1.0)
            };

            if a <= 0.0 {
                bits[idx] = b0 as u8;
                bits[idx + 1] = g0 as u8;
                bits[idx + 2] = r0 as u8;
            } else {
                bits[idx] = (AZUL_B * a + b0 * (1.0 - a)) as u8;
                bits[idx + 1] = (AZUL_G * a + g0 * (1.0 - a)) as u8;
                bits[idx + 2] = (AZUL_R * a + r0 * (1.0 - a)) as u8;
            }
            bits[idx + 3] = 255; // card opaco: a barra nunca abre buraco
        }
    }
}

fn rodar_janela(hwnd_saida: Arc<AtomicUsize>) {
    let classe = wide("RseSplashClasse");
    let titulo = wide("RagnaShield Engine");

    // SAFETY: chamadas de janela/GDI padrão; strings terminam em NUL, e cada
    // recurso criado é liberado antes de sair.
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());

        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.lpszClassName = classe.as_ptr();
        RegisterClassW(&wc);

        let sx = GetSystemMetrics(SM_CXSCREEN);
        let sy = GetSystemMetrics(SM_CYSCREEN);
        let x = (sx - LARGURA) / 2;
        let y = (sy - ALTURA) / 2;

        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            classe.as_ptr(),
            titulo.as_ptr(),
            WS_POPUP | WS_VISIBLE,
            x,
            y,
            LARGURA,
            ALTURA,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null_mut(),
        );
        if hwnd.is_null() {
            return; // sem telinha; o fluxo principal nem fica sabendo
        }
        hwnd_saida.store(hwnd as usize, Ordering::SeqCst);

        // --- prepara o DIB de 32 bits que a janela em camadas usa -------------
        let tela = GetDC(std::ptr::null_mut());
        let memdc = CreateCompatibleDC(tela);

        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = LARGURA;
        bi.bmiHeader.biHeight = -ALTURA; // negativo = top-down, como o nosso buffer
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;

        let mut bits: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let dib = CreateDIBSection(
            memdc,
            &bi,
            DIB_RGB_COLORS,
            &mut bits,
            std::ptr::null_mut(),
            0,
        );

        if !dib.is_null() && !bits.is_null() {
            let total = (LARGURA * ALTURA * 4) as usize;
            let bits_slice = std::slice::from_raw_parts_mut(bits as *mut u8, total);
            // arranca com a base inteira
            bits_slice.copy_from_slice(BASE_BGRA);
            let velho = SelectObject(memdc, dib as *mut _);

            let ponto_janela = POINT { x, y };
            let tam = SIZE {
                cx: LARGURA,
                cy: ALTURA,
            };
            let origem = POINT { x: 0, y: 0 };
            let blend = BLENDFUNCTION {
                BlendOp: AC_SRC_OVER as u8,
                BlendFlags: 0,
                SourceConstantAlpha: 255, // usa o alfa por pixel do DIB
                AlphaFormat: AC_SRC_ALPHA as u8,
            };

            // função local que empurra o DIB atual para a tela
            let pintar = || {
                let mut pj = ponto_janela;
                let mut tm = tam;
                let mut og = origem;
                let mut bl = blend;
                UpdateLayeredWindow(
                    hwnd,
                    tela,
                    &mut pj,
                    &mut tm,
                    memdc,
                    &mut og,
                    0,
                    &mut bl,
                    ULW_ALPHA,
                );
            };

            pintar(); // primeiro quadro (base)

            // --- laço de animação ---------------------------------------------
            let mut n: u32 = 0;
            let mut sair = false;
            while !sair {
                // drena as mensagens sem bloquear (PeekMessage, não GetMessage)
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) > 0 {
                    if msg.message == WM_QUIT {
                        sair = true;
                        break;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                if sair {
                    break;
                }

                desenhar_barra(bits_slice, n);
                pintar();
                n = n.wrapping_add(1);
                std::thread::sleep(std::time::Duration::from_millis(QUADRO_MS));
            }

            SelectObject(memdc, velho);
            DeleteObject(dib as *mut _);
        } else {
            // Sem DIB não há como pintar. Ainda assim seguramos um laço de
            // mensagens para o WM_CLOSE poder fechar a janela limpo.
            let mut msg: MSG = std::mem::zeroed();
            loop {
                if PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) > 0 {
                    if msg.message == WM_QUIT {
                        break;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(QUADRO_MS));
                }
            }
        }

        DeleteDC(memdc);
        ReleaseDC(std::ptr::null_mut(), tela);
    }
}

/// SAFETY: assinatura de WNDPROC. Só encaminha o fechamento.
unsafe extern "system" fn wndproc(hwnd: HWND, msg: UINT, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // SAFETY: handles válidos vindos das mensagens do Windows.
    unsafe {
        match msg {
            WM_CLOSE => {
                winapi::um::winuser::DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}
