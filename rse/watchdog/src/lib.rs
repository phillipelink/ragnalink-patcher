//! `rse_watchdog.dll` — a DLL do RagnaShield Engine, injetada no Ragexe.
//!
//! # O que ela faz nesta fase (5a)
//!
//! Prova que esta viva e conversando: conecta no pipe do Loader, faz o aperto de
//! mao cifrado (HELLO / HELLO_ACK) e mantem o heartbeat. Enquanto ela responde,
//! o Loader sabe que o cliente esta sob vigilancia; quando ela some, o Loader
//! derruba o cliente, e quando o Loader some, ela derruba a si mesma.
//!
//! # O que ainda NAO faz (Fases 5b e 5c)
//!
//! - **netgate**: interceptar o envio de rede e antepor o packet `0x0AAA` com o
//!   ticket. E o que fecha o circuito de verdade com o login-server. Fase 5b.
//! - **integridade**: CRC/SHA das GRFs e dos arquivos criticos. Fase 5c.
//!
//! # Por que o `DllMain` e minimo
//!
//! `DllMain` roda sob o *loader lock* do Windows. Fazer qualquer coisa nao
//! trivial ali - criar thread que ja trabalha, alocar muito, tocar em outra DLL -
//! e receita de deadlock. Entao `DllMain` nao faz nada: quem inicia o RSE e a
//! `rse_configure`, chamada pelo Loader por uma `CreateRemoteThread` propria,
//! DEPOIS que a injecao terminou e o lock ja foi solto.

#![cfg_attr(not(windows), allow(dead_code))]

mod mensagens;

#[cfg(windows)]
mod canal;
#[cfg(windows)]
mod sys;

#[cfg(windows)]
mod dll {
    use crate::{canal, sys};
    use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
    use winapi::um::processthreadsapi::CreateThread;
    use winapi::um::winnt::DLL_PROCESS_ATTACH;

    /// Ponto de entrada da DLL. Faz o minimo possivel — ver o cabecalho.
    #[no_mangle]
    pub extern "system" fn DllMain(_inst: HINSTANCE, motivo: DWORD, _reserved: LPVOID) -> BOOL {
        // Nao desabilitamos as notificacoes de thread (DisableThreadLibraryCalls)
        // porque a Fase 5b pode querer saber de threads novas. Por ora, so
        // ignoramos tudo que nao seja o attach.
        let _ = motivo;
        let _ = DLL_PROCESS_ATTACH;
        TRUE
    }

    /// Recebe a configuracao do Loader e liga o RSE.
    ///
    /// Chamada pelo Loader via `CreateRemoteThread` apontando para este simbolo,
    /// com `param` = endereco do blob de config na nossa memoria. Assinatura de
    /// `LPTHREAD_START_ROUTINE`: `extern "system" fn(LPVOID) -> DWORD`.
    ///
    /// Nao bloqueia: valida a config, cria a thread de trabalho do RSE, e
    /// retorna. O Loader entao manda o HELLO e espera o HELLO_ACK antes de
    /// retomar o jogo.
    #[no_mangle]
    pub extern "system" fn rse_configure(param: LPVOID) -> DWORD {
        // Ler e interpretar a config aqui, na thread do Loader, para poder
        // devolver um codigo de erro que ele veja no `GetExitCodeThread`. Se
        // isto falhar, o Loader nem chega a mandar o HELLO.
        let blob = match unsafe { sys::ler_config_da_memoria(param as *const u8) } {
            Ok(b) => b,
            Err(_) => return 1, // config ilegivel
        };

        // A config e movida para dentro da thread. A `K_s` vive so la, e e
        // zerada quando a thread termina (Zeroize no Key).
        let cfg = match rse_protocol::dll_config::parse(&blob) {
            Ok(c) => c,
            Err(_) => return 2, // config malformada
        };

        // A thread de trabalho e quem faz o canal. `CreateThread` aqui e seguro:
        // ja estamos fora do loader lock (esta funcao roda numa thread propria
        // que o Loader criou, nao no DllMain).
        let ctx = Box::into_raw(Box::new(cfg));
        // SAFETY: thread_worker tem a assinatura de LPTHREAD_START_ROUTINE; ctx e
        // um Box vazado que ela reassume e libera.
        let h = unsafe {
            CreateThread(
                std::ptr::null_mut(),
                0,
                Some(thread_worker),
                ctx as LPVOID,
                0,
                std::ptr::null_mut(),
            )
        };
        if h.is_null() {
            // Recupera o Box para nao vazar, e sinaliza falha.
            // SAFETY: ctx acabou de sair de Box::into_raw e a thread nao nasceu.
            drop(unsafe { Box::from_raw(ctx) });
            return 3;
        }
        // SAFETY: handle valido; nao vamos esperar por ela aqui.
        unsafe { winapi::um::handleapi::CloseHandle(h) };
        0
    }

    /// Corpo da thread de trabalho do RSE.
    extern "system" fn thread_worker(param: LPVOID) -> DWORD {
        // SAFETY: param e o Box::into_raw de rse_configure; reassumimos a posse.
        let cfg = unsafe { Box::from_raw(param as *mut rse_protocol::dll_config::DllConfig) };

        let resultado = canal::rodar(&cfg.pipe_name, &cfg.session_key, &cfg.session_id);

        // A config (e a K_s dentro dela) e zerada AQUI, ao sair de escopo.
        drop(cfg);

        match resultado {
            // Encerramento limpo (SHUTDOWN do Loader): so a thread termina, o
            // jogo segue fechando por conta propria.
            Ok(()) => 0,
            // Qualquer falha do canal - inclusive perder o Loader - e evento de
            // seguranca: o cliente nao pode continuar sem vigilancia.
            Err(_) => sys::matar_o_proprio_processo(),
        }
    }
}
