//! O ícone do RagnaShield na bandeja do sistema (ao lado do relógio).
//!
//! # Para que ele existe
//!
//! É o que o Vanguard, o GameGuard e o EAC fazem, e pela mesma razão: dar ao
//! jogador uma forma de **ver** que a proteção está ativa, em vez de confiar. E,
//! para o suporte, vira a primeira pergunta útil — *"o escudo aparece do lado do
//! relógio?"* separa "o RSE nem subiu" de "o RSE subiu e o problema é outro".
//!
//! # Por que no Loader, e não na DLL
//!
//! O Loader vive **exatamente** o tempo da sessão protegida: nasce no clique em
//! JOGAR e fica no `manter_heartbeat` até o jogo fechar. Então o tempo do ícone
//! na tela é, literalmente, o tempo em que existe proteção — o ícone não pode
//! mentir. A DLL vive dentro do processo do jogo e não deve criar UI própria.
//!
//! # Mesmo princípio da telinha: cosmético não derruba funcional
//!
//! Roda em **thread própria**, com laço de mensagens próprio. Se a janela não
//! nascer, se o ícone não for aceito pelo shell, se qualquer coisa falhar aqui, a
//! vigilância segue intacta e o jogo abre igual. Nenhum caminho desta thread
//! consegue impedir o `manter_heartbeat`.

#![cfg(windows)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::{HBITMAP, HICON, HWND};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::shellapi::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
};
use winapi::um::wingdi::{
    CreateBitmap, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
};
use winapi::um::winuser::{
    CreateIconIndirect, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyWindow,
    DispatchMessageW, GetMessageW, PostMessageW, PostQuitMessage, RegisterClassW,
    RegisterWindowMessageW, TranslateMessage, HWND_MESSAGE, ICONINFO, MSG, WM_APP, WM_CLOSE,
    WM_DESTROY, WNDCLASSW,
};

/// O escudo do RagnaShield, 32×32 BGRA premultiplicado.
///
/// # De onde vem a arte, e por que ela mudou
///
/// A primeira versão recortava o escudo do logo grande (o mesmo do splash). Não
/// funcionou: aquele logo é uma **renderização** — o escudo tem sombra, brilho
/// e degradê fino, e o recorte pegava só a parte de cima. Na bandeja virava um
/// borrão em forma de coroa, sem base: ninguém reconhecia um escudo ali.
///
/// Esta versão vem de uma arte **em pixel art** (grade nativa de 33×42 blocos).
/// Pixel art sobrevive à redução porque já é feita de blocos chapados com
/// contorno duro — reduzir mistura poucas cores, não centenas. Duas
/// consequências práticas:
///
/// * o **contorno escuro** continua visível quando a barra de tarefas é clara;
/// * o **aro prateado** continua visível quando a barra é escura.
///
/// Ou seja, o ícone se defende nos dois temas do Windows sem precisar de dois
/// arquivos. A redução usa filtro de área (BOX) sobre a arte já quantizada na
/// grade nativa, e o escudo fica em 28×32 centrado na caixa de 32 — 28 e não
/// 32 porque esticar até a largura toda engorda o escudo e come o aro.
///
/// Não tentamos gerar um 16×16 dedicado: foi testado, e forçar contorno e
/// paleta a 16 px transforma o desenho em ruído. Quem reduz melhor aqui é o
/// próprio Windows, partindo destes 32 px.
///
/// A arte de referência (PNG com alfa) fica em `arte/icone_32.png`, para quem
/// for reeditar depois sem precisar refazer a extração.
static ICONE_BGRA: &[u8] = include_bytes!("icone_bgra.bin");
const LADO: i32 = 32;

/// Mensagem do ícone para a nossa janela. Não tratamos nada dela hoje (não há
/// menu), mas o `uCallbackMessage` precisa ser válido para o shell entregar os
/// eventos de mouse — inclusive os que fazem a dica aparecer.
const WM_BANDEJA: UINT = WM_APP + 1;

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Alça do ícone: guarda a HWND para poder fechar, e a thread para dar join.
pub struct Bandeja {
    hwnd: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Bandeja {
    /// Põe o escudo na bandeja. Nunca falha de forma a atrapalhar o chamador.
    pub fn mostrar(dica: &str) -> Bandeja {
        let hwnd = Arc::new(AtomicUsize::new(0));
        let hwnd_thread = hwnd.clone();
        let dica = dica.to_string();
        let thread = std::thread::spawn(move || {
            rodar(hwnd_thread, &dica);
        });
        Bandeja {
            hwnd,
            thread: Some(thread),
        }
    }

    /// Tira o ícone da bandeja. Chamada quando o jogo fechou — o ícone some junto
    /// com a proteção, que é a única coisa que ele promete.
    pub fn fechar(mut self) {
        let h = self.hwnd.load(Ordering::SeqCst);
        if h != 0 {
            // SAFETY: h é uma HWND válida criada pela thread da bandeja; postar
            // WM_CLOSE é seguro de qualquer thread.
            unsafe { PostMessageW(h as HWND, WM_CLOSE, 0, 0) };
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn rodar(hwnd_saida: Arc<AtomicUsize>, dica: &str) {
    let classe = wide("RseBandejaClasse");

    // SAFETY: chamadas de janela/shell padrão; strings terminam em NUL e cada
    // recurso criado é liberado antes de sair.
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());

        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.lpszClassName = classe.as_ptr();
        RegisterClassW(&wc);

        // Janela SÓ de mensagem (HWND_MESSAGE): não aparece na tela, não entra na
        // barra de tarefas, não rouba foco. Existe apenas para o shell ter para
        // onde mandar os eventos do ícone.
        let hwnd = CreateWindowExW(
            0,
            classe.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            hinst,
            std::ptr::null_mut(),
        );
        if hwnd.is_null() {
            return; // sem ícone; o fluxo principal nem fica sabendo
        }
        hwnd_saida.store(hwnd as usize, Ordering::SeqCst);

        let icone = criar_icone();
        let mut dados = montar_dados(hwnd, icone, dica);
        Shell_NotifyIconW(NIM_ADD, &mut dados);

        // Se o Explorer reiniciar (acontece), a bandeja inteira é recriada e todo
        // ícone some. O shell avisa com esta mensagem registrada; reagir a ela é
        // o que impede o escudo de sumir para sempre depois de um susto do
        // Explorer — e um ícone que sumiu sozinho seria lido como "a proteção
        // caiu", que é pior do que não ter ícone.
        let taskbar_criada = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr());

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            if taskbar_criada != 0 && msg.message == taskbar_criada {
                Shell_NotifyIconW(NIM_ADD, &mut dados);
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        Shell_NotifyIconW(NIM_DELETE, &mut dados);
        if !icone.is_null() {
            DestroyIcon(icone);
        }
    }
}

/// Monta a estrutura do ícone. `szTip` é o texto que aparece ao passar o mouse.
///
/// SAFETY: chamada dentro do bloco `unsafe` de `rodar`; `hwnd` e `icone` válidos.
unsafe fn montar_dados(hwnd: HWND, icone: HICON, dica: &str) -> NOTIFYICONDATAW {
    // SAFETY: `zeroed` é válido para esta struct de POD; os campos são
    // preenchidos logo abaixo.
    let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    d.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    d.hWnd = hwnd;
    d.uID = 1;
    d.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    d.uCallbackMessage = WM_BANDEJA;
    d.hIcon = icone;

    // A dica é montada num array LOCAL e atribuída de uma vez. `NOTIFYICONDATAW`
    // é `packed`: pegar referência a um campo dela (`&mut d.szTip[..]`) seria um
    // acesso desalinhado — erro no compilador moderno, e comportamento indefinido
    // de qualquer forma. Copiar o array inteiro não referencia nada.
    //
    // `szTip` tem 128 u16 CONTANDO o NUL; truncamos para o NUL sempre caber.
    let texto = wide(dica);
    let mut tip = [0u16; 128];
    let n = texto.len().min(tip.len() - 1);
    tip[..n].copy_from_slice(&texto[..n]);
    d.szTip = tip;
    d
}

/// Constrói o `HICON` a partir dos bytes BGRA embutidos.
///
/// Um ícone de 32 bits precisa de duas bitmaps: a colorida (com o alfa) e a
/// máscara. Com alfa por pixel a máscara é ignorada na prática, mas a API exige
/// que ela exista — uma máscara 1bpp zerada é o que se usa.
///
/// SAFETY: chamada dentro do bloco `unsafe` de `rodar`.
unsafe fn criar_icone() -> HICON {
    // SAFETY: chamadas GDI padrão; cada objeto criado é liberado antes de sair, e
    // a cópia para `bits` respeita o tamanho do DIB (32×32×4 = ICONE_BGRA.len()).
    unsafe {
        let memdc = CreateCompatibleDC(std::ptr::null_mut());
        if memdc.is_null() {
            return std::ptr::null_mut();
        }

        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = LADO;
        bi.bmiHeader.biHeight = -LADO; // negativo = top-down, como o nosso buffer
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
        if dib.is_null() || bits.is_null() {
            DeleteDC(memdc);
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(ICONE_BGRA.as_ptr(), bits as *mut u8, ICONE_BGRA.len());

        // Máscara 1bpp zerada: com alfa por pixel, quem manda é o canal alfa.
        let mascara: HBITMAP = CreateBitmap(LADO, LADO, 1, 1, std::ptr::null());

        let mut info: ICONINFO = std::mem::zeroed();
        info.fIcon = 1; // ícone, não cursor
        info.hbmMask = mascara;
        info.hbmColor = dib;
        let icone = CreateIconIndirect(&mut info);

        // As bitmaps são copiadas pelo CreateIconIndirect; as nossas podem sair.
        DeleteObject(dib as *mut _);
        if !mascara.is_null() {
            DeleteObject(mascara as *mut _);
        }
        DeleteDC(memdc);
        icone
    }
}

/// SAFETY: assinatura de WNDPROC.
unsafe extern "system" fn wndproc(hwnd: HWND, msg: UINT, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // SAFETY: handles válidos vindos das mensagens do Windows.
    unsafe {
        match msg {
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            // WM_BANDEJA chega a cada movimento de mouse sobre o ícone. Não há
            // menu hoje; o DefWindowProc dá conta.
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}
