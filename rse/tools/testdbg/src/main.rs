//! `rse-testdbg` — anexa um depurador de teste ao cliente, para exercitar a
//! detecção `3001 DEBUGGER_ATTACHED` da Fase 6.
//!
//! ```text
//! cargo run -p rse-testdbg            # anexa por 90 s ao RagnaLinK_ptBR5.exe
//! cargo run -p rse-testdbg -- 30      # por 30 s
//! ```
//!
//! # Por que esta ferramenta existe
//!
//! Testar a detecção exigiria baixar um x64dbg ou instalar o Visual Studio
//! completo. Não precisa: **depurador não é uma categoria de programa, é um
//! processo que chamou `DebugActiveProcess`**. Esta ferramenta chama a mesma
//! API, então o Windows marca o alvo como "sendo depurado" exatamente do mesmo
//! jeito — e as quatro checagens do `deteccoes.rs` acendem igual.
//!
//! # 🚨 Dois cuidados que mantêm o jogo vivo
//!
//! 1. **`DebugSetProcessKillOnExit(FALSE)`.** Por padrão o Windows **mata o
//!    processo depurado** quando o depurador sai. Sem esta linha, testar a
//!    detecção fecharia o jogo — e pareceria que o RSE derrubou o cliente.
//! 2. **O laço de eventos.** Um processo sendo depurado **congela** a cada evento
//!    de depuração até o depurador responder. Se a gente só anexasse e dormisse,
//!    o jogo travaria na primeira DLL carregada. Por isso o laço responde tudo
//!    com `DBG_CONTINUE`: anexado, mas sem interferir.

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
    use std::time::{Duration, Instant};

    use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
    use winapi::um::debugapi::{
        ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, WaitForDebugEvent,
    };

    // O `winapi 0.3` nao expoe esta, e ela e a MAIS importante do arquivo: sem
    // ela, sair daqui mata o processo depurado — ou seja, testar a deteccao
    // fecharia o jogo do jogador. Declarada a mao; mora no kernel32 desde o XP.
    extern "system" {
        fn DebugSetProcessKillOnExit(KillOnExit: winapi::shared::minwindef::BOOL)
            -> winapi::shared::minwindef::BOOL;
    }
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::minwinbase::DEBUG_EVENT;
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    const DBG_CONTINUE: DWORD = 0x0001_0002;
    const ALVO_PADRAO: &str = "RagnaLinK_ptBR5.exe";

    pub fn executar() {
        let segundos: u64 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(90);

        let alvo = ALVO_PADRAO;
        let pid = match achar_pid(alvo) {
            Some(p) => p,
            None => {
                eprintln!(
                    "nao achei o processo {}. Abra o jogo pelo launcher primeiro.",
                    alvo
                );
                std::process::exit(1);
            }
        };
        println!("alvo: {} (pid {})", alvo, pid);

        // SAFETY: chamadas de API de depuracao; pid vem da varredura de processos.
        unsafe {
            if DebugActiveProcess(pid) == 0 {
                let e = GetLastError();
                eprintln!(
                    "DebugActiveProcess falhou (erro {}). Erro 5 = acesso negado: \
                     rode este comando como o MESMO usuario que abriu o jogo.",
                    e
                );
                std::process::exit(1);
            }

            // 🚨 ANTES de qualquer outra coisa: sem isto, sair daqui MATA o jogo.
            if DebugSetProcessKillOnExit(FALSE) == 0 {
                eprintln!("aviso: nao consegui desligar o kill-on-exit; o jogo pode fechar ao final");
            }
        }

        println!(
            "depurador anexado. Segurando por {} s — o RagnaShield deve acusar \
             3001 em ate 30 s.",
            segundos
        );
        println!("(o jogo continua jogavel: respondemos os eventos com DBG_CONTINUE)");

        bombear_eventos(Duration::from_secs(segundos));

        // SAFETY: pid ainda e o processo que anexamos.
        unsafe {
            DebugActiveProcessStop(pid);
        }
        println!("depurador desanexado. Em ate 30 s deve aparecer 'ambiente voltou ao normal'.");
    }

    /// Responde aos eventos de depuração para o alvo não congelar.
    ///
    /// Um processo depurado para em CADA evento (DLL carregada, thread criada,
    /// exceção) e só volta quando o depurador chama `ContinueDebugEvent`. Um
    /// depurador que dorme é um jogo travado.
    fn bombear_eventos(duracao: Duration) {
        let inicio = Instant::now();
        // SAFETY: DEBUG_EVENT e POD; a API preenche.
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };

        while inicio.elapsed() < duracao {
            // 100 ms de espera: curto para o laco reagir ao tempo, longo para
            // nao girar a CPU a toa.
            // SAFETY: `ev` e valido pelo tempo da chamada.
            let houve = unsafe { WaitForDebugEvent(&mut ev, 100) };
            if houve != 0 {
                // SAFETY: os ids vieram do evento que acabamos de receber.
                unsafe {
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                }
            }
        }
    }

    /// Primeiro processo com este nome de executável.
    fn achar_pid(nome: &str) -> Option<u32> {
        // SAFETY: snapshot de processos; o handle e fechado abaixo.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }

        // SAFETY: PROCESSENTRY32W e POD; dwSize e obrigatorio antes do primeiro uso.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut achado = None;
        // SAFETY: snap valido; `e` preenchido pela API a cada passo.
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
