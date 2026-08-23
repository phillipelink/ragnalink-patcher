//! `rse-testhandle` — abre um handle de escrita no cliente, para exercitar a
//! detecção `3003` da Fase 6.4b.
//!
//! ```text
//! cargo run -p rse-testhandle            # segura o handle por 120 s
//! cargo run -p rse-testhandle -- 60      # por 60 s
//! ```
//!
//! # O que esta ferramenta prova, e por que ela se chama assim
//!
//! Repare no nome do executável: **`rse-testhandle.exe`**. Não há nada de
//! "cheat" nele, e ele não está em lista nenhuma. A 6.4 (`processos.rs`) o
//! ignora completamente.
//!
//! Mesmo assim a 6.4b vai acusá-lo — porque ele faz a única coisa que um editor
//! de memória externo **não pode deixar de fazer**: abre um `HANDLE` para o
//! processo do jogo com `PROCESS_VM_WRITE`.
//!
//! É exatamente a demonstração do que a 6.4b acrescenta: o Cheat Engine
//! renomeado, recompilado, ou escrito do zero por alguém que vende "bypass"
//! continua precisando deste handle. Se ele não abrir, não escreve na memória.
//! Se abrir, aparece aqui.
//!
//! # Por que ela só ABRE o handle e não escreve nada
//!
//! Escrever na memória do jogo travaria o cliente ou corromperia estado, e não
//! provaria nada além do que já está provado: a detecção olha a **capacidade**
//! (a máscara de acesso do handle), não o ato. Abrir basta — e é a diferença
//! entre `3003 REMOTE_HANDLE_WRITE_CAPABLE` e o `3002 REMOTE_MEMORY_WRITE`, que
//! fica reservado para quando um dia pegarmos a escrita acontecendo.
//!
//! Fora isso: uma ferramenta de teste que corrompe o processo alvo é uma
//! ferramenta que ninguém roda duas vezes.

fn main() {
    #[cfg(not(windows))]
    {
        eprintln!("esta ferramenta so faz sentido no Windows");
        std::process::exit(2);
    }

    #[cfg(windows)]
    win::executar();
}

#[cfg(windows)]
mod win {
    use std::time::Duration;

    use winapi::shared::minwindef::MAX_PATH;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    const ALVO_PADRAO: &str = "RagnaLinK_ptBR5.exe";

    // As mesmas máscaras que o `handles.rs` procura. Pedimos as quatro para o
    // relatório sair com a lista completa e ficar óbvio o que foi detectado.
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    pub fn executar() {
        let segundos: u64 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(120);

        let pid = match achar_pid(ALVO_PADRAO) {
            Some(p) => p,
            None => {
                eprintln!(
                    "nao achei o processo {}. Abra o jogo pelo launcher primeiro.",
                    ALVO_PADRAO
                );
                std::process::exit(1);
            }
        };

        let direitos = PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION;

        // SAFETY: pid veio da varredura de processos; o handle é fechado abaixo.
        let h = unsafe { OpenProcess(direitos, 0, pid) };
        if h.is_null() {
            // SAFETY: chamada logo apos a falha, na mesma thread.
            let e = unsafe { GetLastError() };
            eprintln!(
                "OpenProcess falhou (erro {}). Erro 5 = acesso negado: rode como \
                 o MESMO usuario que abriu o jogo.",
                e
            );
            std::process::exit(1);
        }

        println!("alvo: {} (pid {})", ALVO_PADRAO, pid);
        println!("handle aberto com VM_WRITE | VM_OPERATION | VM_READ | CREATE_THREAD");
        println!();
        println!("  Repare: este programa se chama 'rse-testhandle.exe'.");
        println!("  Nao esta em lista de proibidos nenhuma — a 6.4 nao o ve.");
        println!("  A 6.4b ve, porque ela olha o handle, nao o nome.");
        println!();
        println!("  O RagnaShield varre handles a cada 60 s. Esperado no servidor:");
        println!("    RSE: violacao 3003 sev=alta detalhe=handle com escrita no cliente:");
        println!("         rse-testhandle.exe (pid ...) acesso=0x... [VM_WRITE VM_OPERATION CREATE_THREAD]");
        println!();
        println!("segurando por {} s...", segundos);

        std::thread::sleep(Duration::from_secs(segundos));

        // SAFETY: handle válido que abrimos acima.
        unsafe { CloseHandle(h) };
        println!("handle fechado. Ele some do proximo relatorio.");
    }

    /// Primeiro processo com este nome de executável.
    fn achar_pid(nome: &str) -> Option<u32> {
        // SAFETY: snapshot de processos; o handle é fechado abaixo.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }

        // SAFETY: PROCESSENTRY32W é POD; dwSize é obrigatório antes do 1º uso.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut achado = None;
        // SAFETY: snap válido; `e` preenchido pela API a cada passo.
        unsafe {
            if Process32FirstW(snap, &mut e) != 0 {
                loop {
                    let fim = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
                    let atual = String::from_utf16_lossy(&e.szExeFile[..fim]);
                    if atual.eq_ignore_ascii_case(nome) {
                        achado = Some(e.th32ProcessID);
                        break;
                    }
                    if Process32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        achado
    }
}
