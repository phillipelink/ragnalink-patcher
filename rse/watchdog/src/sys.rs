//! Toda a conversa com a API do Windows fica aqui.
//!
//! Concentrar o `unsafe` num arquivo so e uma decisao deliberada: o resto da DLL
//! (`canal`, `mensagens`) e Rust seguro e testavel em qualquer maquina. Se algo
//! der errado com um handle ou um ponteiro, o problema esta neste arquivo, e so
//! nele.

#![cfg(windows)]

use std::ptr;

use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::namedpipeapi::WaitNamedPipeW;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId};
use winapi::um::synchapi::Sleep;
use winapi::um::namedpipeapi::SetNamedPipeHandleState;
use winapi::um::winnt::{
    HANDLE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn pid_atual() -> u32 {
    // SAFETY: chamada sem parametros, nunca falha.
    unsafe { GetCurrentProcessId() }
}

pub fn tid_atual() -> u32 {
    // SAFETY: idem.
    unsafe { GetCurrentThreadId() }
}

/// Endereco base do modulo principal do processo (o proprio Ragexe).
///
/// So para diagnostico — vai no HELLO_ACK. `GetModuleHandleW(NULL)` devolve a
/// base do executavel, que e um numero estavel que ajuda a casar este processo
/// com o que o Loader criou.
pub fn base_do_modulo() -> u64 {
    // SAFETY: NULL pede o modulo do proprio processo; sempre existe.
    let h: HMODULE = unsafe { GetModuleHandleW(ptr::null()) };
    h as usize as u64
}

pub fn dormir_ms(ms: u32) {
    // SAFETY: Sleep nao tem como falhar.
    unsafe { Sleep(ms) }
}

/// Encerra o proprio processo — o `SelfKill` da maquina de estados da DLL.
///
/// Codigo de saida 0xB5E (RSE... mais ou menos) para o encerramento ser
/// distinguivel de uma saida normal do jogo num rastreio.
pub fn matar_o_proprio_processo() -> ! {
    use winapi::um::processthreadsapi::TerminateProcess;
    // SAFETY: GetCurrentProcess devolve um pseudo-handle valido; TerminateProcess
    // com ele nao retorna.
    unsafe {
        TerminateProcess(GetCurrentProcess(), 0xB5E);
    }
    // TerminateProcess nao retorna, mas o compilador nao sabe disso.
    loop {
        dormir_ms(1000);
    }
}

/// Cliente de named pipe, no lado da DLL.
pub struct Pipe {
    h: HANDLE,
}

// SAFETY: o handle e um valor opaco valido em todo o processo; esta estrutura e
// dona unica dele.
unsafe impl Send for Pipe {}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.h != INVALID_HANDLE_VALUE && !self.h.is_null() {
            // SAFETY: dono unico, handle ainda aberto.
            unsafe { CloseHandle(self.h) };
        }
    }
}

impl Pipe {
    /// Conecta ao pipe do Loader, tentando ate o prazo.
    pub fn conectar(nome: &str, timeout_ms: u32) -> Result<Pipe, String> {
        let caminho = if nome.starts_with(r"\\.\pipe\") {
            nome.to_string()
        } else {
            format!(r"\\.\pipe\{}", nome)
        };
        let caminho_w = wide(&caminho);
        let inicio = std::time::Instant::now();
        let prazo = std::time::Duration::from_millis(timeout_ms as u64);

        loop {
            // SAFETY: caminho_w termina em NUL; demais parametros sao constantes
            // ou nulos aceitos pela assinatura.
            let h = unsafe {
                CreateFileW(
                    caminho_w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                let pipe = Pipe { h };
                pipe.modo_mensagem()?;
                return Ok(pipe);
            }

            // SAFETY: leitura do ultimo erro da thread.
            let erro = unsafe { GetLastError() };
            if inicio.elapsed() >= prazo {
                return Err(format!("pipe {} indisponivel (erro {})", caminho, erro));
            }
            // SAFETY: mesma string com NUL.
            unsafe { WaitNamedPipeW(caminho_w.as_ptr(), 200) };
        }
    }

    /// Poe o pipe em modo mensagem: cada `ReadFile` devolve um frame inteiro, que
    /// e o que o `frame.rs` espera. Sem isto, um `ReadFile` poderia cortar um
    /// frame ao meio ou juntar dois.
    fn modo_mensagem(&self) -> Result<(), String> {
        let mut modo: DWORD = winapi::um::winbase::PIPE_READMODE_MESSAGE;
        // SAFETY: handle valido; passamos um ponteiro para um DWORD valido.
        let ok = unsafe {
            SetNamedPipeHandleState(self.h, &mut modo, ptr::null_mut(), ptr::null_mut())
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro.
            let erro = unsafe { GetLastError() };
            return Err(format!("SetNamedPipeHandleState falhou (erro {})", erro));
        }
        Ok(())
    }

    /// Le um frame. Em modo mensagem, um `ReadFile` = um frame.
    ///
    /// O `timeout_ms` aqui e informativo: o prazo de verdade e o do proprio pipe,
    /// configurado pelo Loader ao criar. Mantido na assinatura para o chamador
    /// documentar a intencao, e para uma versao futura com pipe assincrono.
    pub fn ler(&self, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        // Frame maximo: cabecalho(24) + payload(8192) + tag(16) = 8232. Um buffer
        // um pouco maior cobre com folga.
        let mut buf = vec![0u8; 9000];
        let mut lidos: DWORD = 0;
        // SAFETY: handle valido; buf tem espaco para `buf.len()` bytes; lidos
        // recebe a contagem.
        let ok = unsafe {
            ReadFile(
                self.h,
                buf.as_mut_ptr() as *mut _,
                buf.len() as DWORD,
                &mut lidos,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro.
            let erro = unsafe { GetLastError() };
            return Err(format!("ReadFile no pipe falhou (erro {})", erro));
        }
        buf.truncate(lidos as usize);
        Ok(buf)
    }

    pub fn escrever(&self, dados: &[u8]) -> Result<(), String> {
        let mut escritos: DWORD = 0;
        // SAFETY: handle valido; dados aponta para memoria valida de dados.len().
        let ok = unsafe {
            WriteFile(
                self.h,
                dados.as_ptr() as *const _,
                dados.len() as DWORD,
                &mut escritos,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro.
            let erro = unsafe { GetLastError() };
            return Err(format!("WriteFile no pipe falhou (erro {})", erro));
        }
        if escritos as usize != dados.len() {
            return Err(format!("escrevi {} de {} bytes", escritos, dados.len()));
        }
        Ok(())
    }
}

/// Le o blob de configuracao que o Loader escreveu na nossa memoria.
///
/// # SAFETY
///
/// `ptr` tem que apontar para uma regiao valida com pelo menos
/// `DLL_CONFIG_HEADER_LEN` bytes legiveis; o cabecalho diz o tamanho total, e so
/// entao lemos o resto. Quem chama e a `rse_configure`, e o ponteiro vem do
/// proprio Loader via `CreateRemoteThread` - nao ha caminho por onde um valor
/// arbitrario chegue aqui.
pub unsafe fn ler_config_da_memoria(ptr: *const u8) -> Result<Vec<u8>, String> {
    use rse_protocol::dll_config::DLL_CONFIG_HEADER_LEN;

    if ptr.is_null() {
        return Err("ponteiro de configuracao nulo".to_string());
    }
    // Primeiro o cabecalho, para saber o tamanho do nome do pipe.
    let mut cabecalho = [0u8; DLL_CONFIG_HEADER_LEN];
    // SAFETY: contrato da funcao garante DLL_CONFIG_HEADER_LEN bytes legiveis.
    ptr::copy_nonoverlapping(ptr, cabecalho.as_mut_ptr(), DLL_CONFIG_HEADER_LEN);

    // O byte 5 e o tamanho do nome do pipe (ver dll_config).
    let tam_pipe = cabecalho[5] as usize;
    let total = DLL_CONFIG_HEADER_LEN + tam_pipe;

    let mut blob = vec![0u8; total];
    // SAFETY: o Loader escreveu `total` bytes contiguos; tam_pipe vem do proprio
    // cabecalho que ele montou.
    ptr::copy_nonoverlapping(ptr, blob.as_mut_ptr(), total);
    Ok(blob)
}
