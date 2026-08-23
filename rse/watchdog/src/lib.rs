//! `rse_watchdog.dll` — a DLL do RagnaShield Engine, injetada no Ragexe.
//!
//! # O que ela faz (5a + 5b)
//!
//! - **5a — canal:** conecta no pipe do Loader, faz o aperto de mao cifrado
//!   (HELLO / HELLO_ACK) e mantem o heartbeat. Enquanto ela responde, o Loader
//!   sabe que o cliente esta sob vigilancia; quando ela some, o Loader derruba o
//!   cliente, e quando o Loader some, ela derruba a si mesma.
//! - **5b — netgate:** engancha o `send` do Winsock e antepoe o packet `0x0AAA`
//!   (o ticket, que chega no HELLO) na conexao de login. E esta peca que faz
//!   `rse_enforce: on` significar alguma coisa — sem ela, abrir o Ragexe direto
//!   ainda conectava. Ver `netgate.rs`.
//!
//! # O que ainda NAO faz (Fase 5c)
//!
//! - **integridade**: CRC/SHA das GRFs e dos arquivos criticos, e o REPORT das
//!   violacoes para o Loader.
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
// Declarado sem `cfg`: a parte que decide o que é suspeito é pura, e os testes
// dela rodam em qualquer máquina. Só o pedaço que fala com o Toolhelp é
// `#[cfg(windows)]`, lá dentro.
mod modulos;

// Sem `cfg`: a decisão (o que mudou entre duas fotos) é pura e testável; só a
// leitura da memória e a travessia do PE precisam do Windows.
mod codigo;

#[cfg(windows)]
mod canal;
#[cfg(windows)]
mod deteccoes;
#[cfg(windows)]
mod handles;
#[cfg(windows)]
mod integridade;
#[cfg(windows)]
mod processos;
// Sem `cfg`: a decisão (comparar dois relógios) é pura e testável em qualquer
// máquina; só as leituras são de Windows. Ver o cabeçalho do arquivo.
mod relogio;
#[cfg(windows)]
mod netgate;
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

// ===========================================================================
//  Guarda contra colisão de código de violação
// ===========================================================================

/// Duas colisões de código aconteceram na Fase 6, e **as duas foram pegas por
/// acaso** — uma porque fui conferir o spec, outra porque um arquivo faltando
/// obrigou a olhar o crate inteiro. Nenhuma das duas teria quebrado a
/// compilação, e é isso que as torna perigosas: o sintoma é um log ambíguo,
/// meses depois, na hora em que ele mais importa.
///
/// Este teste lê os próprios fontes e falha se dois `const COD_*` diferentes
/// apontarem para o mesmo número. É um teste sobre o código-fonte, não sobre o
/// comportamento — feio, e o único jeito de pegar isto, já que as constantes são
/// privadas de cada módulo e nunca se encontram em lugar nenhum em tempo de
/// compilação.
#[cfg(test)]
mod codigos {
    use std::collections::BTreeMap;

    #[test]
    fn nenhum_codigo_de_violacao_colide() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut por_numero: BTreeMap<u16, Vec<String>> = BTreeMap::new();

        let entradas = std::fs::read_dir(dir).expect("nao consegui ler src/");
        for e in entradas {
            let caminho = e.expect("entrada invalida").path();
            if caminho.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let arquivo = caminho
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            let texto = std::fs::read_to_string(&caminho).expect("nao consegui ler o arquivo");

            for linha in texto.lines() {
                let t = linha.trim();
                if !t.starts_with("const COD_") {
                    continue;
                }
                // const COD_ALGUMA_COISA: u16 = 1234;
                let (nome, resto) = match t.split_once(':') {
                    Some(p) => p,
                    None => continue,
                };
                let valor = match resto.split('=').nth(1) {
                    Some(v) => v,
                    None => continue,
                };
                let numero: u16 = match valor
                    .trim()
                    .trim_end_matches(';')
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.trim_end_matches(';').parse().ok())
                {
                    Some(n) => n,
                    None => continue,
                };
                let nome = nome.trim_start_matches("const ").trim().to_string();
                por_numero
                    .entry(numero)
                    .or_default()
                    .push(format!("{} ({})", nome, arquivo));
            }
        }

        assert!(
            !por_numero.is_empty(),
            "nao achei nenhum `const COD_*` — o teste parou de enxergar os fontes, \
             o que e pior do que uma colisao: ele passaria para sempre sem olhar nada"
        );

        let colisoes: Vec<String> = por_numero
            .iter()
            .filter(|(_, donos)| donos.len() > 1)
            .map(|(n, donos)| format!("  {} <- {}", n, donos.join("  E  ")))
            .collect();

        assert!(
            colisoes.is_empty(),
            "codigo de violacao usado por mais de um lugar:\n{}\n\n\
             Consulte rse/docs/CODIGOS.md e o RSE_SPEC §9 antes de escolher um numero.",
            colisoes.join("\n")
        );
    }
}
