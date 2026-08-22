//! `rse_loader` — o processo que abre o Ragexe sob protecao do RagnaShield Engine.
//!
//! ```text
//! rse_loader.exe --pipe <nome> --auth <url> --exe <caminho absoluto>
//!                [--dir <pasta>] [--timeout-ms N] [--log <arquivo>]
//!                [-- <argumentos repassados ao Ragexe>]
//! ```
//!
//! # O lugar dele no desenho
//!
//! ```text
//! launcher  --(pipe: credencial)-->  LOADER  --(HTTPS: ticket)-->  Auth Service
//!                                      |
//!                                      +--(CreateProcessW)-->  Ragexe
//! ```
//!
//! O launcher **nao sabe nada** de anti-cheat: ele abre uma sessao, entrega a
//! credencial e sai. Toda a logica de protecao vive aqui e na DLL da Fase 5.
//! Essa separacao e o ponto central da arquitetura - trocar a estrategia de
//! protecao nao deve exigir tocar no launcher.
//!
//! # O que ele NAO faz nesta fase
//!
//! Injecao de DLL, heartbeat e watchdog sao **Fase 5**. Nesta fase o Loader
//! prova o encanamento: recebe a credencial sem que ela passe por linha de
//! comando, obtem um ticket de verdade, e abre o jogo com os argumentos
//! intactos. O ponto de injecao esta marcado em `jogo.rs`.
//!
//! # Duas armadilhas do Windows que este binario tem que respeitar
//!
//! 1. **O diretorio de trabalho.** Processo elevado criado pelo servico AppInfo
//!    nasce com CWD em `C:\Windows\System32`, nao na pasta de quem chamou. O
//!    Ragexe carrega `data.grf` e afins por caminho relativo - se o CWD estiver
//!    errado, ele abre e nao acha nada. Por isso `--dir` existe e por isso
//!    `jogo.rs` chama `CreateProcessW` com `lpCurrentDirectory` explicito.
//! 2. **Caminhos relativos.** Pelo mesmo motivo, `--exe` **tem** que vir
//!    absoluto. O launcher resolve antes de chamar; aqui so se confere.

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(windows), allow(dead_code))]
// Sem console para o jogador. Em release o Loader vira uma aplicacao de janela
// (a telinha do RagnaShield e a unica UI) - fim do CMD que piscava ao clicar em
// JOGAR. O diagnostico NAO se perde: o log continua indo para rse_loader.log; so
// o eco no console (os println!) e que passa a cair no vazio. Em build de debug o
// console fica, que e onde ele e util no desenvolvimento.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

mod auth;
#[cfg(windows)]
mod injecao;
mod jogo;
#[cfg(windows)]
mod splash;
mod tubo;

/// Prazo padrao para receber a credencial do launcher.
///
/// Generoso de proposito: o launcher so escreve depois que o UAC foi aceito, e
/// o jogador pode demorar para clicar em "Sim".
const TIMEOUT_HANDOVER_MS: u32 = 120_000;

struct Args {
    pipe: String,
    auth: String,
    exe: PathBuf,
    dir: Option<PathBuf>,
    timeout_ms: u32,
    log: Option<PathBuf>,
    /// Caminho da rse_watchdog.dll. Padrao: ao lado do rse_loader.exe.
    dll: Option<PathBuf>,
    /// Se true, o jogo NAO abre quando a injecao da DLL falha. Padrao false:
    /// enquanto o rollout esta em `log`, um problema de injecao nao deve trancar
    /// o jogador fora — o login-server ainda nem exige o ticket. Vira `true` na
    /// virada para `on`.
    exigir_dll: bool,
    /// Repassados ao Ragexe sem interpretacao. E aqui que o `1sak1` viaja.
    jogo_args: Vec<String>,
}

fn uso() -> ! {
    eprintln!(
        "rse_loader — inicia o Ragexe sob protecao do RagnaShield Engine\n\
         \n\
         USO:\n  \
           rse_loader.exe --pipe <nome> --auth <url> --exe <caminho> [opcoes] [-- <args>]\n\
         \n\
         OBRIGATORIOS:\n  \
           --pipe <nome>     nome do named pipe onde o launcher entrega a credencial\n  \
           --auth <url>      base do RSE Auth Service (ex.: https://site/rse/v1)\n  \
           --exe  <caminho>  Ragexe, em caminho ABSOLUTO\n\
         \n\
         OPCOES:\n  \
           --dir <pasta>       diretorio de trabalho do jogo (padrao: pasta do --exe)\n  \
           --dll <caminho>     rse_watchdog.dll (padrao: ao lado do rse_loader.exe)\n  \
           --exigir-dll        nao abre o jogo se a injecao da DLL falhar\n  \
           --timeout-ms <N>    prazo para receber a credencial (padrao 120000)\n  \
           --log <arquivo>     grava diagnostico neste arquivo\n  \
           -- <args...>        tudo depois disto vai para o Ragexe intacto\n"
    );
    std::process::exit(2)
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        pipe: String::new(),
        auth: String::new(),
        exe: PathBuf::new(),
        dir: None,
        timeout_ms: TIMEOUT_HANDOVER_MS,
        log: None,
        dll: None,
        exigir_dll: false,
        jogo_args: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            // Tudo depois de `--` e do jogo. Nao interpretamos NADA daqui para
            // a frente - e o que garante que o `1sak1` chega como saiu.
            "--" => {
                a.jogo_args.extend(it);
                break;
            }
            "--pipe" => a.pipe = it.next().unwrap_or_else(|| uso()),
            "--auth" => a.auth = it.next().unwrap_or_else(|| uso()),
            "--exe" => a.exe = PathBuf::from(it.next().unwrap_or_else(|| uso())),
            "--dir" => a.dir = Some(PathBuf::from(it.next().unwrap_or_else(|| uso()))),
            "--dll" => a.dll = Some(PathBuf::from(it.next().unwrap_or_else(|| uso()))),
            "--exigir-dll" => a.exigir_dll = true,
            "--log" => a.log = Some(PathBuf::from(it.next().unwrap_or_else(|| uso()))),
            "--timeout-ms" => {
                a.timeout_ms = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(TIMEOUT_HANDOVER_MS)
            }
            "-h" | "--help" => uso(),
            outro => {
                eprintln!("argumento desconhecido: {}\n", outro);
                uso()
            }
        }
    }

    if a.pipe.is_empty() || a.auth.is_empty() || a.exe.as_os_str().is_empty() {
        uso()
    }
    if !a.exe.is_absolute() {
        bail!(
            "--exe precisa ser absoluto (recebido: {}). Processo elevado nasce \
             com o diretorio de trabalho em System32, entao caminho relativo \
             aponta para o lugar errado.",
            a.exe.display()
        );
    }
    Ok(a)
}

/// Diretorio de trabalho do jogo.
///
/// Sem `--dir`, usa a pasta do proprio executavel - que e o que o Ragexe espera
/// e o que ele tinha quando o launcher o abria diretamente.
fn diretorio_do_jogo(a: &Args) -> Result<PathBuf> {
    if let Some(d) = &a.dir {
        return Ok(d.clone());
    }
    a.exe
        .parent()
        .map(|p| p.to_path_buf())
        .context("nao consegui deduzir a pasta do jogo a partir do --exe")
}

/// Log que vai para o console E para um arquivo.
///
/// # Por que o arquivo importa mais do que parece
///
/// Este processo vive por poucos segundos e fecha o proprio console junto. Na
/// maquina do jogador, "vi um preto piscar" e tudo o que sobra - e e exatamente
/// nesse caso que voce precisa saber o que aconteceu. Sem arquivo, cada suporte
/// vira adivinhacao.
///
/// O caminho padrao fica ao lado do executavel do jogo, que e uma pasta que o
/// jogador sabe achar e para a qual ele ja tem permissao de escrita.
struct LogDuplo {
    arquivo: std::sync::Mutex<Option<std::fs::File>>,
}

impl log::Log for LogDuplo {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let linha = format!("[{}] {}", r.level(), r.args());
        println!("{}", linha);
        if let Ok(mut guarda) = self.arquivo.lock() {
            if let Some(f) = guarda.as_mut() {
                use std::io::Write;
                // Falha ao gravar nao pode derrubar o Loader: o log e
                // diagnostico, nao funcionalidade. Perder uma linha e melhor
                // do que o jogo nao abrir por causa de disco cheio.
                let _ = writeln!(f, "{}", linha);
                let _ = f.flush();
            }
        }
    }

    fn flush(&self) {}
}

fn iniciar_log(caminho: &Option<PathBuf>, exe: &Path) {
    // Sem `--log`, grava ao lado do jogo. Nome fixo e sobrescrito a cada
    // execucao: o interessante e sempre a ultima tentativa, e um arquivo que
    // cresce para sempre na pasta do jogador seria falta de educacao.
    let destino = caminho.clone().unwrap_or_else(|| {
        exe.parent()
            .unwrap_or_else(|| Path::new("."))
            .join("rse_loader.log")
    });

    let arquivo = std::fs::File::create(&destino).ok();
    let tinha_arquivo = arquivo.is_some();

    let logger = Box::new(LogDuplo {
        arquivo: std::sync::Mutex::new(arquivo),
    });

    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }

    if tinha_arquivo {
        log::info!("log em {}", destino.display());
    } else {
        println!("(nao consegui criar {}; log so no console)", destino.display());
    }
}

fn executar() -> Result<()> {
    let args = parse_args()?;
    iniciar_log(&args.log, &args.exe);

    log::info!(
        "rse_loader iniciando — protocolo {}",
        rse_protocol::version::RSE_PROTOCOL
    );

    // A telinha do RagnaShield sobe já — enquanto o jogador vê o logo, o Loader
    // faz sessão, ticket, injeção e handshake por baixo. Ela é fechada logo após
    // o jogo ser retomado. Roda em thread própria e nunca atrapalha nada.
    #[cfg(windows)]
    let tela = splash::Splash::mostrar();

    // --- 1. credencial, pelo pipe -----------------------------------------
    //
    // Bloqueia ate o launcher escrever. Se o jogador demorar no UAC, esperamos;
    // se o launcher morrer, o prazo expira e saimos com erro claro.
    let credencial = tubo::receber_credencial(&args.pipe, args.timeout_ms)
        .context("nao recebi a credencial de sessao do launcher")?;
    log::info!("credencial recebida ({} bytes)", credencial.len());

    // --- 2. ticket, pelo Auth Service --------------------------------------
    //
    // O ticket vale 30 s. Pedimos AGORA, imediatamente antes de abrir o jogo,
    // para gastar o minimo possivel dessa janela.
    //
    // O hash do cliente e informativo nesta fase: o servidor registra o que
    // existe em campo antes de comecar a exigir. Se a leitura falhar (arquivo
    // em uso, permissao), seguimos com zeros em vez de impedir o jogo de abrir -
    // negar acesso por causa de um campo que ninguem ainda usa seria trocar um
    // problema real por um inventado.
    let client_hash = match auth::hash_do_cliente(&args.exe) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("nao consegui calcular o hash do cliente ({:#}); seguindo com zeros", e);
            "0".repeat(64)
        }
    };

    let ticket = auth::pedir_ticket_com_hash(&args.auth, &credencial, &client_hash)
        .context("o Auth Service nao emitiu o ticket")?;
    log::info!(
        "ticket recebido: {} bytes, key_id={}, vale por {} ms",
        ticket.bytes.len(),
        ticket.key_id,
        ticket.expira_em_ms
    );

    // --- 3. o jogo ---------------------------------------------------------
    let dir = diretorio_do_jogo(&args)?;

    // Estas tres linhas existem para o diagnostico de campo. "O jogo nao abre"
    // e um relato inutil; "a linha de comando era X e o diretorio era Y" e
    // resolvivel. Nao ha segredo aqui - a credencial nunca passa por argumento.
    log::info!("exe   : {}", args.exe.display());
    log::info!("dir   : {}", dir.display());
    log::info!(
        "linha : {}",
        jogo::montar_linha_de_comando(&args.exe.display().to_string(), &args.jogo_args)
    );
    if args.jogo_args.is_empty() {
        log::warn!(
            "NENHUM argumento para o jogo. O cliente hexed do RagnaLinK espera \
             a chave (ex.: 1sak1) e recusa abrir sem ela."
        );
    }

    let filho = jogo::iniciar_suspenso(&args.exe, &dir, &args.jogo_args)
        .context("nao consegui criar o processo do jogo")?;
    log::info!("Ragexe criado suspenso, pid={}", filho.pid);

    // --- 4. kill-switch de arranque ----------------------------------------
    //
    //  Antes de injetar, o Loader consulta a politica. Se ela manda recuar
    //  ('off'), abrimos o jogo SEM injetar — o freio de emergencia. RSE quebrado
    //  em producao vira um ajuste no Auth Service, e os lancamentos novos passam
    //  a abrir limpos, sem redistribuir cliente. Isto vem ANTES do --exigir-dll
    //  de proposito: o freio ganha do modo estrito.
    let rse_desligado = kill_switch_de_arranque(&args.auth);

    // --- 5. injetar a DLL e apertar a mao ANTES de retomar -----------------
    //
    //  A ordem NAO e negociavel: injetar -> esperar HELLO_ACK -> so entao
    //  ResumeThread. Retomar antes do HELLO_ACK abre uma janela em que o jogo ja
    //  roda sem vigilancia - curta, mas suficiente, e e exatamente a que um
    //  atacante procura.
    let canal = if rse_desligado {
        Err(anyhow::anyhow!("kill-switch ativo pela politica"))
    } else {
        injetar(&args, &filho, &ticket.bytes, &credencial, &client_hash)
    };

    // --- 6. retomar --------------------------------------------------------
    match &canal {
        Ok(_) => {}
        Err(_) if rse_desligado => {
            // Kill-switch: nao e falha, e decisao. Abre sem protecao e ignora o
            // --exigir-dll — o freio de emergencia manda mais que o modo estrito.
            log::warn!(
                "KILL-SWITCH ATIVO pela politica — abrindo o jogo SEM injetar a DLL \
                 (--exigir-dll ignorado de proposito)"
            );
        }
        Err(e) if args.exigir_dll => {
            // Em modo estrito, injecao falha = jogo NAO abre. O processo suspenso
            // e encerrado ao sair (o Drop do ProcessoFilho fecha os handles; o
            // processo suspenso sem ninguem para retomar morre com eles).
            bail!("injecao da DLL falhou e --exigir-dll esta ligado: {:#}", e);
        }
        Err(e) => {
            // Modo padrao (rollout): abre assim mesmo, mas grita no log. Enquanto
            // o login-server esta em 'log', nao ha protecao real a perder, e
            // trancar o jogador fora seria pior do que o problema.
            log::error!("injecao da DLL FALHOU, abrindo SEM protecao: {:#}", e);
        }
    }

    jogo::retomar(&filho).context("nao consegui retomar o processo do jogo")?;
    log::info!("Ragexe retomado");

    // O jogo está de pé — a telinha já cumpriu seu papel. O `fechar` cuida do
    // respiro (segura o logo por um mínimo e cobre a janela do jogo enquanto ela
    // pinta, sem flash preto). Ele NÃO segura a proteção: o jogo já foi retomado
    // e a DLL já está de pé — o que espera ali é só o pixel.
    #[cfg(windows)]
    tela.fechar();

    // --- 6. vigiar ---------------------------------------------------------
    //
    //  Daqui em diante o Loader nao tem mais nada a fazer senao responder o
    //  heartbeat da DLL ate o jogo fechar. Se a DLL parar de bater, o
    //  `manter_heartbeat` retorna e o Loader sai — e a DLL, do outro lado, se
    //  encerra por conta propria ao perder o Loader.
    #[cfg(windows)]
    if let Ok(mut c) = canal {
        if let Err(e) = c.manter_heartbeat() {
            log::warn!("vigilancia encerrada: {:#}", e);
        }
    }

    Ok(())
}

/// Consulta a política no arranque, para o kill-switch. Devolve `true` se o RSE
/// deve recuar (abrir o jogo sem injetar).
///
/// Falha de rede **não** desliga o RSE: o kill-switch é um `"off"` explícito de
/// um serviço no ar, não uma inferência de queda. E o ticket acabou de vir, então
/// o serviço está no ar — uma falha aqui é estranha, e a resposta segura é seguir
/// COM proteção, não desligar tudo por um soluço de rede.
fn kill_switch_de_arranque(auth_url: &str) -> bool {
    match auth::consultar_politica(auth_url) {
        Ok(p) => {
            log::info!("politica: enforce={}, epoch={}", p.enforce, p.policy_epoch);
            let off = p.loader_desligado();
            if off {
                log::warn!("a politica esta em 'off' — kill-switch do Loader ativo");
            }
            off
        }
        Err(e) => {
            log::warn!("nao consegui consultar a politica ({:#}); seguindo COM protecao", e);
            false
        }
    }
}

/// Resolve o caminho da DLL e faz a injeção. Isolada para o `cfg` não poluir o
/// fluxo principal.
#[cfg(windows)]
fn injetar(
    args: &Args,
    filho: &jogo::ProcessoFilho,
    ticket: &[u8],
    credencial: &str,
    client_hash: &str,
) -> Result<injecao::CanalDll> {
    let dll = args.dll.clone().unwrap_or_else(|| {
        // Padrao: ao lado do proprio rse_loader.exe.
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("rse_watchdog.dll")))
            .unwrap_or_else(|| PathBuf::from("rse_watchdog.dll"))
    });
    log::info!("injetando {}", dll.display());

    let alvo = injecao::AlvoProcesso(jogo::handle_do_processo(filho));
    // `args.auth`, a credencial e o hash vão junto: é com eles que o Loader
    // renova o ticket quando a DLL pede (TICKET_REQ).
    injecao::injetar_e_apertar_mao(alvo, &dll, ticket, &args.auth, credencial, client_hash)
}

#[cfg(not(windows))]
fn injetar(
    _args: &Args,
    _filho: &jogo::ProcessoFilho,
    _ticket: &[u8],
    _credencial: &str,
    _client_hash: &str,
) -> Result<()> {
    bail!("injecao so no Windows")
}

fn main() {
    if let Err(e) = executar() {
        log::error!("{:#}", e);
        // Codigo 1 = falhou. O launcher nao espera por ele nesta fase, mas a
        // Fase 5 vai, e um codigo honesto agora evita retrabalho depois.
        std::process::exit(1);
    }
}
