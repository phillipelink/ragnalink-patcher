//! Limite de clientes simultâneos por computador.
//!
//! # De onde vem o número
//!
//! Da **política do servidor** (`GET /policy` → `max_clients`), e não de um
//! arquivo no cliente. É de propósito: o limite herda a mesma virtude do
//! kill-switch — você muda no Auth Service e vale no próximo JOGAR de todo mundo,
//! sem redistribuir binário. `0` (o padrão) significa **sem limite**.
//!
//! # Como a contagem funciona, e por que mutex e não semáforo
//!
//! Cada cliente protegido segura **um mutex nomeado** — `RSE_vaga_0`,
//! `RSE_vaga_1`, … Ao subir, o Loader tenta possuir a primeira vaga livre; se
//! todas estiverem ocupadas, o limite foi atingido.
//!
//! A escolha do mutex é o ponto delicado. Um semáforo pareceria mais natural
//! ("conte até N"), mas a contagem de um semáforo **não é devolvida quando o
//! processo morre**: um cliente que travasse e fosse morto no Gerenciador de
//! Tarefas vazaria a vaga para sempre, e o jogador ficaria trancado sem entender
//! por quê. Mutex do Windows tem posse: se o dono morre, o sistema marca a vaga
//! como `WAIT_ABANDONED` e o próximo a pedir **recebe** a vaga. O caso de erro
//! se conserta sozinho, sem watchdog nenhum.
//!
//! Os nomes ficam no espaço `Local\`, que é por sessão de logon do Windows. Dois
//! usuários diferentes no mesmo PC (troca rápida de usuário) têm contagens
//! separadas — que é o comportamento razoável para "clientes por computador" na
//! prática, e evita precisar de privilégio para o espaço `Global\`.
//!
//! # 🚨 O que este limite É, e o que ele NÃO é
//!
//! Isto é **cumprimento de política para jogador honesto**, não barreira contra
//! adversário. Roda na máquina dele: quem trocar o `rse_loader.exe` por um que
//! ignore a contagem abre quantos clientes quiser. O que impede a troca do Loader
//! é o ticket — mas o ticket é emitido **antes** desta checagem, então um Loader
//! adulterado ainda conseguiria um.
//!
//! O limite **autoritativo** teria que ser contado no servidor, por `machine_fp`
//! (que já viaja no ticket, bytes 52–84): o login-server recusaria o terceiro
//! login vindo da mesma impressão de máquina. Enquanto isso não existir, este
//! limite resolve o caso real — o jogador que abre três clientes porque dá — e
//! não resolve o caso do sujeito determinado. Está registrado assim no ROADMAP
//! para ninguém confundir uma coisa com a outra depois.

#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use std::ptr;

use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use winapi::um::winbase::{WAIT_ABANDONED, WAIT_OBJECT_0};
use winapi::um::winnt::HANDLE;

/// Uma vaga ocupada. Enquanto viver, o cliente conta para o limite; ao ser
/// destruída (ou ao processo morrer), a vaga volta para o bolo.
pub struct Vaga {
    handle: HANDLE,
}

// SAFETY: um HANDLE do Windows é um valor opaco válido em todo o processo, e
// esta estrutura é a única dona dele.
unsafe impl Send for Vaga {}

impl Drop for Vaga {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: dono único; possuímos o mutex desde `reservar`.
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Tenta reservar uma vaga.
///
/// - `Ok(None)`  — não há limite configurado (`max == 0`); nada a fazer.
/// - `Ok(Some)`  — vaga obtida; segure-a enquanto o cliente viver.
/// - `Err(())`   — todas as vagas ocupadas: o limite foi atingido.
pub fn reservar(max: u32) -> Result<Option<Vaga>, ()> {
    if max == 0 {
        return Ok(None);
    }

    for i in 0..max {
        let nome = wide(&format!("Local\\RSE_vaga_{}", i));
        // SAFETY: `nome` termina em NUL; os demais parâmetros são padrão.
        let h = unsafe { CreateMutexW(ptr::null_mut(), 0, nome.as_ptr()) };
        if h.is_null() {
            continue; // não deu para criar esta vaga; tenta a próxima
        }

        // Prazo zero: ou a vaga está livre agora, ou seguimos adiante. Esperar
        // seria pior — o jogador ficaria olhando a telinha sem saber por quê.
        //
        // SAFETY: handle válido recém-criado.
        let r = unsafe { WaitForSingleObject(h, 0) };
        if r == WAIT_OBJECT_0 || r == WAIT_ABANDONED {
            // WAIT_ABANDONED = o dono anterior morreu sem soltar. A vaga é nossa,
            // e é exatamente o caso que o mutex conserta sozinho.
            return Ok(Some(Vaga { handle: h }));
        }

        // Ocupada por outro cliente vivo: fecha nosso handle e tenta a seguinte.
        // SAFETY: handle válido que não possuímos.
        unsafe { CloseHandle(h) };
    }

    Err(())
}
