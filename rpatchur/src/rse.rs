//! Fachada do RagnaShield Engine dentro do launcher.
//!
//! # O ponto mais importante deste arquivo
//!
//! O launcher **nao conhece a logica de anti-cheat**, e isso e proposital. Tudo
//! o que ele faz aqui e:
//!
//! 1. abrir uma sessao no Auth Service;
//! 2. criar um pipe e entregar a credencial por ele;
//! 3. disparar o `rse_loader.exe`, elevado, com os argumentos do jogo intactos.
//!
//! Verificacao de integridade, deteccao, heartbeat e ticket vivem no Loader e na
//! DLL. Trocar a estrategia de protecao inteira nao deveria exigir tocar em
//! nenhuma linha do `rpatchur/` - e essa e a medida de que a separacao esta
//! certa.
//!
//! # Por que a credencial vai por pipe e nao por linha de comando
//!
//! Linha de comando de processo e publica: qualquer coisa rodando na maquina le
//! com `wmic process get commandline`. O plano original (ADR-004) era handle
//! herdado, mas herdar handle exige `CreateProcess`, e o Loader precisa nascer
//! **elevado** para conseguir injetar a DLL no Ragexe - o que so o
//! `ShellExecuteExW` com verbo `runas` faz, e ele nao herda handles.
//!
//! O pipe resolve os dois: some da linha de comando e atravessa a fronteira de
//! elevacao. Detalhe do formato em `rse_protocol::handover`.
//!
//! # A corrida que este arquivo tem que evitar
//!
//! O `play.exit_on_success` e `true`: o launcher fecha assim que dispara o jogo.
//! Se ele fechar antes de o Loader ler a credencial, o pipe morre junto e o jogo
//! nao abre. Por isso a espera explicita em [`launch_protected`] - e por isso ela
//! tem prazo, para uma falha do Loader nao deixar a janela parada para sempre.

use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::patcher::RseConfiguration;

/// Prazo para o Loader conectar no pipe e ler a credencial.
///
/// Conta a partir de DEPOIS do UAC: o `ShellExecuteExW` so retorna quando o
/// jogador ja decidiu. Um Loader saudavel gasta milissegundos aqui; 15 s so
/// existe para um antivirus que resolva inspecionar o executavel antes.
const TIMEOUT_HANDOVER: Duration = Duration::from_secs(15);

/// Resultado da tentativa, para a interface poder dizer algo util.
pub enum Saida {
    /// O jogo foi disparado sob protecao.
    Iniciado,
    /// Falhou, mas a politica manda abrir o jogo sem protecao.
    CairParaSemProtecao(String),
    /// O Auth Service RECUSOU a sessao (banido / build barrado). Diferente de
    /// falha tecnica: o jogo NAO abre, tentar de novo nao resolve, e a mensagem
    /// para o jogador e outra. Nao passa pela politica `allow`.
    Bloqueado(String),
}

/// A sessao pode voltar com a credencial, ou com uma recusa deliberada.
enum ResultadoSessao {
    Credencial(String),
    Bloqueado(String),
}

/// Abre o jogo sob protecao do RSE.
///
/// `client_arguments` atravessa **intacto** ate o Ragexe - e por aqui que o
/// `"1sak1"` viaja. Nem esta funcao nem o Loader interpretam esses valores.
pub fn launch_protected(
    cfg: &RseConfiguration,
    play_path: &str,
    client_arguments: &[String],
) -> Result<Saida> {
    match tentar(cfg, play_path, client_arguments) {
        // Iniciado OU Bloqueado: os dois sao desfechos legitimos, nao falha. Um
        // bloqueio (banimento) NAO passa pela politica `allow` de proposito — ele
        // e uma decisao do servidor, nao uma indisponibilidade.
        Ok(saida) => Ok(saida),
        Err(e) => {
            // A politica de indisponibilidade e uma decisao de OPERACAO, nao de
            // codigo. Em piloto, `allow` evita que um Auth Service instavel
            // impeca todo mundo de jogar; em producao, `block` e o que faz o RSE
            // valer alguma coisa. Ver decisao D5 no ROADMAP.
            if cfg.on_service_unavailable.eq_ignore_ascii_case("allow") {
                log::warn!("RSE falhou ({:#}); politica 'allow', abrindo sem protecao", e);
                Ok(Saida::CairParaSemProtecao(format!("{:#}", e)))
            } else {
                Err(e)
            }
        }
    }
}

fn tentar(cfg: &RseConfiguration, play_path: &str, client_arguments: &[String]) -> Result<Saida> {
    // --- caminhos absolutos ------------------------------------------------
    //
    // Processo elevado nasce com o diretorio de trabalho em System32. Tudo o que
    // for para o Loader tem que estar resolvido ANTES, aqui, onde o diretorio
    // ainda e o da instalacao.
    let base = pasta_do_executavel()?;
    let loader = base.join(&cfg.loader_path);
    let jogo = base.join(play_path);

    if !loader.exists() {
        bail!(
            "nao encontrei o RSE Loader em {}. Confira `rse.loader_path` no YAML.",
            loader.display()
        );
    }
    if !jogo.exists() {
        bail!("nao encontrei o cliente em {}", jogo.display());
    }

    // --- 1. sessao ---------------------------------------------------------
    //
    // O Auth Service pode recusar a sessao de propria vontade (banimento, build
    // barrado). Isso NAO e falha tecnica: sai como `Bloqueado`, com mensagem
    // propria, e nem chega a criar pipe ou disparar o Loader.
    let credencial = match abrir_sessao(cfg).context("o Auth Service nao abriu a sessao")? {
        ResultadoSessao::Bloqueado(motivo) => return Ok(Saida::Bloqueado(motivo)),
        ResultadoSessao::Credencial(c) => c,
    };

    // --- 2. pipe -----------------------------------------------------------
    //
    // Criado ANTES de disparar o Loader, sempre. Se o Loader criasse, haveria
    // uma janela em que o nome ja e conhecido e o objeto ainda nao existe -
    // e qualquer processo do mesmo usuario poderia ocupar aquele nome primeiro.
    let nome_pipe = nome_de_pipe_aleatorio()?;
    let servidor = plataforma::criar_pipe(&nome_pipe)
        .with_context(|| format!("nao consegui criar o pipe {}", nome_pipe))?;

    // A entrega roda em outra thread para o `recv_timeout` la embaixo poder
    // desistir. Se ela ficar presa, o encerramento do processo a leva junto.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = plataforma::entregar_credencial(servidor, &credencial);
        let _ = tx.send(r.map_err(|e| format!("{:#}", e)));
    });

    // --- 3. Loader, elevado ------------------------------------------------
    let args = plataforma::montar_argumentos_do_loader(
        &nome_pipe,
        &cfg.auth_url,
        &jogo,
        client_arguments,
    );
    plataforma::disparar_loader(&loader, &base, &args)
        .context("nao consegui iniciar o RSE Loader")?;

    // --- 4. esperar a leitura ANTES de deixar o launcher fechar -------------
    match rx.recv_timeout(TIMEOUT_HANDOVER) {
        Ok(Ok(())) => {
            log::info!("RSE: credencial entregue ao Loader");
            Ok(Saida::Iniciado)
        }
        Ok(Err(e)) => Err(anyhow!("falha ao entregar a credencial: {}", e)),
        Err(_) => bail!(
            "o RSE Loader nao leu a credencial em {} s. Ele foi bloqueado por \
             antivirus, ou o executavel esta corrompido?",
            TIMEOUT_HANDOVER.as_secs()
        ),
    }
}

/// Pasta do executavel do launcher.
///
/// Nao usa `current_dir()`: o diretorio de trabalho depende de como o programa
/// foi aberto (atalho com "Iniciar em" diferente, por exemplo), e a instalacao
/// nao depende. Mesmo raciocinio do `resolver_index_url` em `patcher/config.rs`.
fn pasta_do_executavel() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("nao consegui descobrir o proprio caminho")?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("o executavel nao tem pasta pai"))
}

/// Nome de pipe com 128 bits de entropia.
///
/// Aleatorio para que ninguem consiga ocupar o nome antes; o pipe ja e
/// protegido por DACL, mas nome previsivel e um convite desnecessario.
fn nome_de_pipe_aleatorio() -> Result<String> {
    use rse_protocol::crypto::{to_hex, OsRandom, RandomSource};
    let mut bytes = [0u8; 16];
    OsRandom
        .fill(&mut bytes)
        .map_err(|_| anyhow!("o sistema nao forneceu entropia"))?;
    Ok(format!("rse-{}", to_hex(&bytes)))
}

// ===========================================================================
//  Auth Service
// ===========================================================================

#[derive(serde::Deserialize)]
struct RespostaSessao {
    session_credential: String,
}

/// Abre a sessao e devolve a credencial.
///
/// Usa o cliente HTTP bloqueante de proposito: isto roda no caminho do clique em
/// JOGAR, que ja e sincrono hoje (o `ShellExecuteExW` do `start_executable`
/// tambem bloqueia enquanto o UAC esta na tela).
fn abrir_sessao(cfg: &RseConfiguration) -> Result<ResultadoSessao> {
    let url = format!("{}/session", cfg.auth_url.trim_end_matches('/'));

    let cliente = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.unwrap_or(8000)))
        .build()?;

    let corpo = serde_json::json!({
        "protocol": rse_protocol::version::RSE_PROTOCOL,
        "launcherBuild": build_do_launcher(),
        "machineHint": "0".repeat(64),
        "lastPatchIndex": 0,
        "osVersion": std::env::consts::OS,
    });

    let resposta = cliente.post(&url).json(&corpo).send()?;
    let status = resposta.status();
    let texto = resposta.text().unwrap_or_default();

    // 403 = o Auth Service recusa de proposito (banimento, build barrado). E uma
    // decisao dele, nao um defeito — vira `Bloqueado`, com a mensagem do servidor.
    // Qualquer outro nao-2xx e falha tecnica (rseErro).
    if status.as_u16() == 403 {
        return Ok(ResultadoSessao::Bloqueado(motivo_curto(&texto)));
    }
    if !status.is_success() {
        bail!("HTTP {} de {} — {}", status, url, texto.trim());
    }
    let r: RespostaSessao = serde_json::from_str(&texto)
        .with_context(|| format!("resposta inesperada do Auth Service: {}", texto))?;
    Ok(ResultadoSessao::Credencial(r.session_credential))
}

/// Extrai uma mensagem legivel do corpo de erro do Auth Service ({error,message}
/// ou texto cru), curta o bastante para caber numa linha da interface.
fn motivo_curto(corpo: &str) -> String {
    #[derive(serde::Deserialize)]
    struct E {
        #[serde(default)]
        message: String,
        #[serde(default)]
        error: String,
    }
    if let Ok(e) = serde_json::from_str::<E>(corpo) {
        let m = if !e.message.is_empty() { e.message } else { e.error };
        if !m.is_empty() {
            return m.chars().take(160).collect();
        }
    }
    let t = corpo.trim();
    if t.is_empty() {
        "acesso recusado".to_string()
    } else {
        t.chars().take(160).collect()
    }
}

/// SHA-256 do proprio executavel.
///
/// Nesta fase e informativo - o servidor registra para saber o que existe em
/// campo antes de comecar a exigir. Ver `RseOpcoes.BuildsAceitos` no Auth
/// Service.
fn build_do_launcher() -> String {
    use rse_protocol::crypto::{sha256, to_hex};
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(|b| to_hex(&sha256(&b)))
        .unwrap_or_else(|_| "0".repeat(64))
}

// ===========================================================================
//  Diagnostico para o suporte (ponto L6 — comando `rse_diag`)
// ===========================================================================

/// Gera o relatorio de diagnostico do RSE e devolve um codigo curto de suporte.
///
/// Escreve `rse_diag.txt` ao lado do jogo (junto dos logs do Loader e da DLL) e
/// devolve um codigo tipo `RSE-4F2A` para o jogador passar ao suporte — o mesmo
/// codigo fica gravado no arquivo, entao um casa com o outro. Nao contem segredo:
/// a `auth_url` e publica, e nao ha chave nenhuma do lado do launcher.
pub fn gerar_diagnostico(cfg: &RseConfiguration, play_path: &str, contexto: &str) -> String {
    use rse_protocol::crypto::{sha256, to_hex};

    let base = pasta_do_executavel().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let jogo = base.join(play_path);
    let dir = jogo.parent().map(|p| p.to_path_buf()).unwrap_or(base);

    let agora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut corpo = String::new();
    corpo.push_str("=== RagnaShield Engine — diagnostico ===\n");
    corpo.push_str(&format!("contexto     : {}\n", contexto));
    corpo.push_str(&format!("quando (unix): {}\n", agora));
    corpo.push_str(&format!("protocolo    : {}\n", rse_protocol::version::RSE_PROTOCOL));
    corpo.push_str(&format!("launcher(sha): {}\n", build_do_launcher()));
    corpo.push_str(&format!("auth_url     : {}\n", cfg.auth_url));
    corpo.push_str(&format!("loader_path  : {}\n", cfg.loader_path));
    corpo.push_str(&format!("on_unavail   : {}\n", cfg.on_service_unavailable));
    corpo.push_str(&format!("so           : {}\n", std::env::consts::OS));
    corpo.push_str(&format!("jogo         : {}\n", jogo.display()));
    corpo.push_str("\n--- rse_loader.log (fim) ---\n");
    corpo.push_str(&fim_do_arquivo(&dir.join("rse_loader.log"), 60));
    corpo.push_str("\n\n--- rse_watchdog.log (fim) ---\n");
    corpo.push_str(&fim_do_arquivo(&dir.join("rse_watchdog.log"), 60));

    // Codigo curto: primeiros 4 hex do SHA-256 do corpo (com o `agora` dentro,
    // entao cada diagnostico tem o seu). Calculado ANTES de escrever a linha do
    // codigo, para o valor ser estavel.
    let codigo = format!("RSE-{}", to_hex(&sha256(corpo.as_bytes()))[..4].to_uppercase());
    corpo.push_str(&format!("\ncodigo       : {}\n", codigo));

    let alvo = dir.join("rse_diag.txt");
    if let Err(e) = std::fs::write(&alvo, &corpo) {
        log::warn!("nao consegui gravar {}: {}", alvo.display(), e);
    }
    codigo
}

/// As ultimas `n` linhas de um arquivo de texto (ou um aviso se nao der para ler).
fn fim_do_arquivo(caminho: &std::path::Path, n: usize) -> String {
    match std::fs::read_to_string(caminho) {
        Ok(txt) => {
            let linhas: Vec<&str> = txt.lines().collect();
            let inicio = linhas.len().saturating_sub(n);
            linhas[inicio..].join("\n")
        }
        Err(e) => format!("(sem {}: {})", caminho.display(), e),
    }
}

// ===========================================================================
//  Plataforma
// ===========================================================================

#[cfg(windows)]
mod plataforma {
    use anyhow::{bail, Result};
    use rse_protocol::handover;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
    use winapi::um::fileapi::{FlushFileBuffers, WriteFile};
    use winapi::um::winbase::{
        PIPE_ACCESS_OUTBOUND, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use winapi::um::winnt::HANDLE;

    fn para_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Handle que pode ir para outra thread.
    ///
    /// SAFETY: handle do Windows e um valor opaco valido em todo o processo, e
    /// esta estrutura e a unica dona dele - ninguem mais o usa depois do envio.
    pub struct PipeServidor(HANDLE);
    unsafe impl Send for PipeServidor {}

    impl Drop for PipeServidor {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                // SAFETY: dono unico, handle ainda aberto.
                unsafe {
                    DisconnectNamedPipe(self.0);
                    CloseHandle(self.0);
                }
            }
        }
    }

    /// Cria o pipe de handover.
    ///
    /// `lpSecurityAttributes` fica NULO **de proposito**. O descritor de
    /// seguranca padrao de um named pipe da controle total a quem o criou e nega
    /// aos demais usuarios - que e exatamente o que se quer. Escrever uma DACL a
    /// mao aqui seria mais codigo, sem ganho, e com chance real de ficar mais
    /// permissiva por engano.
    ///
    /// A elevacao nao atrapalha: o Loader elevado e o **mesmo usuario**, e a
    /// politica obrigatoria do Windows e *no-write-up* - integridade alta abre
    /// objeto criado por integridade media, nao o contrario.
    pub fn criar_pipe(nome: &str) -> Result<PipeServidor> {
        let caminho = para_wide(&format!(r"\\.\pipe\{}", nome));

        // SAFETY: `caminho` termina em NUL; os demais parametros sao constantes
        // da API.
        let h = unsafe {
            CreateNamedPipeW(
                caminho.as_ptr(),
                PIPE_ACCESS_OUTBOUND, // so escrevemos; o Loader so le
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,    // uma instancia: um Loader, um pipe
                4096, // buffer de saida
                0,    // buffer de entrada: nao lemos nada
                0,    // timeout padrao
                ptr::null_mut(),
            )
        };

        if h == INVALID_HANDLE_VALUE {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            bail!("CreateNamedPipeW falhou (erro {})", erro);
        }
        Ok(PipeServidor(h))
    }

    /// Espera o Loader conectar, entrega a credencial e confirma a leitura.
    pub fn entregar_credencial(servidor: PipeServidor, credencial: &str) -> Result<()> {
        let quadro = handover::serialize(credencial)
            .map_err(|e| anyhow::anyhow!("nao consegui montar o handover: {}", e))?;

        // SAFETY: handle valido; sem OVERLAPPED, a chamada bloqueia ate um
        // cliente conectar. Esta funcao roda em thread propria justamente por
        // isso - quem chamou desiste por prazo se ela nao voltar.
        let conectado = unsafe { ConnectNamedPipe(servidor.0, ptr::null_mut()) };
        if conectado == 0 {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            // 535 = ERROR_PIPE_CONNECTED: o cliente chegou antes da chamada.
            // Nao e falha - e a corrida normal, e significa que ja estamos
            // conectados.
            const ERROR_PIPE_CONNECTED: u32 = 535;
            if erro != ERROR_PIPE_CONNECTED {
                bail!("ConnectNamedPipe falhou (erro {})", erro);
            }
        }

        let mut escritos: u32 = 0;
        // SAFETY: handle valido; `quadro` aponta para memoria valida de
        // `quadro.len()` bytes.
        let ok = unsafe {
            WriteFile(
                servidor.0,
                quadro.as_ptr() as *const _,
                quadro.len() as u32,
                &mut escritos,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            bail!("WriteFile no pipe falhou (erro {})", erro);
        }
        if escritos as usize != quadro.len() {
            bail!("escrevi {} de {} bytes no pipe", escritos, quadro.len());
        }

        // 🚨 E ESTA linha que impede a corrida com o `exit_on_success`.
        //
        // Num pipe, `FlushFileBuffers` do lado servidor bloqueia ate o cliente
        // ter LIDO tudo. Sem ela, `WriteFile` volta assim que os bytes entram no
        // buffer do kernel - e o launcher poderia fechar (derrubando o pipe)
        // antes de o Loader ler, fazendo o jogo nao abrir de vez em quando.
        // Bug intermitente, que so aparece em maquina lenta.
        //
        // SAFETY: handle valido e conectado.
        let ok = unsafe { FlushFileBuffers(servidor.0) };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            bail!("FlushFileBuffers falhou (erro {})", erro);
        }
        Ok(())
    }

    /// Argumentos do Loader. Nenhum segredo aqui - a credencial vai pelo pipe.
    pub fn montar_argumentos_do_loader(
        nome_pipe: &str,
        auth_url: &str,
        jogo: &Path,
        client_arguments: &[String],
    ) -> Vec<String> {
        let mut v = vec![
            "--pipe".to_string(),
            nome_pipe.to_string(),
            "--auth".to_string(),
            auth_url.to_string(),
            "--exe".to_string(),
            jogo.display().to_string(),
        ];
        if let Some(dir) = jogo.parent() {
            v.push("--dir".to_string());
            v.push(dir.display().to_string());
        }
        // Tudo depois de `--` e do jogo, intacto.
        v.push("--".to_string());
        v.extend(client_arguments.iter().cloned());
        v
    }

    /// Dispara o Loader **sem elevacao**.
    ///
    /// # Por que era `runas`, e por que deixou de ser
    ///
    /// O `RagnaLinK_ptBR5.exe` trazia no manifesto
    /// `requestedExecutionLevel level="requireAdministrator"`, entao o Windows
    /// **recusava** cria-lo sem elevacao. Como o processo filho herda o token do
    /// pai, o Loader tinha que nascer elevado para conseguir criar o jogo — e o
    /// UAC ao clicar em JOGAR vinha dai, nao de uma escolha nossa.
    ///
    /// O manifesto do cliente passou a ser `asInvoker`. Com isso o jogo roda em
    /// integridade media, o Loader tambem, a injecao segue funcionando (media
    /// injeta em media) e **o jogador nao ve UAC nenhum**.
    ///
    /// Tres ganhos, e o terceiro e o que mais importa:
    ///
    /// 1. Menos um clique, para todo mundo, toda vez.
    /// 2. **Conta padrao do Windows volta a funcionar.** Com `runas`, quem nao e
    ///    administrador nao recebe um "Sim/Nao": recebe um pedido de **usuario e
    ///    senha de administrador**. Quem nao tem essa senha — PC de familia, do
    ///    trabalho, notebook gerenciado — simplesmente nao conseguia jogar.
    /// 3. Um injetor **nao** elevado levanta bem menos suspeita de antivirus do
    ///    que um elevado, o que ajuda no problema de assinatura de codigo (D6).
    ///
    /// Quem tiver o cliente antigo (ainda `requireAdministrator`) leva erro 740
    /// no `CreateProcessW`; o Loader traduz isso em "atualize pelo launcher" em
    /// vez de falhar em silencio. Ver `jogo.rs`.
    pub fn disparar_loader(loader: &Path, dir: &Path, args: &[String]) -> Result<()> {
        use winapi::ctypes::c_int;
        use winapi::shared::minwindef::{BOOL, ULONG};
        use winapi::um::shellapi::SHELLEXECUTEINFOW;
        extern "system" {
            pub fn ShellExecuteExW(pExecInfo: *mut SHELLEXECUTEINFOW) -> BOOL;
        }
        const SEE_MASK_CLASSNAME: ULONG = 1;
        const SW_SHOW: c_int = 5;

        let parametros = args
            .iter()
            .map(|a| crate::rse::citar_para_shell(a))
            .collect::<Vec<_>>()
            .join(" ");

        let arquivo = para_wide(loader.to_str().unwrap_or_default());
        let parametros_w = para_wide(&parametros);
        // `lpDirectory` explicito: sem isto o Loader herdaria o diretorio de
        // trabalho do launcher, e um processo elevado criado pelo servico
        // AppInfo pode nascer em System32.
        let diretorio = para_wide(dir.to_str().unwrap_or_default());
        // "open" em vez de "runas": sem pedido de elevacao. O Loader nasce no
        // mesmo nivel de integridade do launcher (media), que e o mesmo do jogo.
        let operacao = para_wide("open");
        let classe = para_wide("exefile");

        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_CLASSNAME,
            hwnd: ptr::null_mut(),
            lpVerb: operacao.as_ptr(),
            lpFile: arquivo.as_ptr(),
            lpParameters: parametros_w.as_ptr(),
            lpDirectory: diretorio.as_ptr(),
            nShow: SW_SHOW,
            hInstApp: ptr::null_mut(),
            lpIDList: ptr::null_mut(),
            lpClass: classe.as_ptr(),
            hkeyClass: ptr::null_mut(),
            dwHotKey: 0,
            hMonitor: ptr::null_mut(),
            hProcess: ptr::null_mut(),
        };

        // SAFETY: todas as strings terminam em NUL e vivem ate o fim da chamada;
        // `info` esta preenchida com o `cbSize` correto.
        let r = unsafe { ShellExecuteExW(&mut info) };
        if r == 0 {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            // 1223 = ERROR_CANCELLED: o jogador clicou "Nao" no UAC. Merece
            // mensagem propria - nao e defeito, e escolha dele.
            const ERROR_CANCELLED: u32 = 1223;
            if erro == ERROR_CANCELLED {
                bail!("o jogador recusou o pedido de elevacao (UAC)");
            }
            bail!("ShellExecuteExW falhou (erro {}) para {}", erro, loader.display());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod plataforma {
    use anyhow::{bail, Result};
    use std::path::Path;

    pub struct PipeServidor;
    pub fn criar_pipe(_nome: &str) -> Result<PipeServidor> {
        bail!("o RSE so funciona no Windows")
    }
    pub fn entregar_credencial(_s: PipeServidor, _c: &str) -> Result<()> {
        bail!("o RSE so funciona no Windows")
    }
    pub fn montar_argumentos_do_loader(
        _n: &str,
        _a: &str,
        _j: &Path,
        _c: &[String],
    ) -> Vec<String> {
        Vec::new()
    }
    pub fn disparar_loader(_l: &Path, _d: &Path, _a: &[String]) -> Result<()> {
        bail!("o RSE so funciona no Windows")
    }
}

/// Citacao para a string unica de parametros do `ShellExecuteExW`.
///
/// Mesma regra do `CommandLineToArgvW` que o Loader usa do outro lado; ver
/// `rse/loader/src/jogo.rs` para a explicacao completa. Precisa existir aqui
/// tambem porque `lpParameters` e **uma string**, nao um vetor.
fn citar_para_shell(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut saida = String::with_capacity(arg.len() + 2);
    saida.push('"');
    let mut barras = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                barras += 1;
                saida.push('\\');
            }
            '"' => {
                for _ in 0..barras {
                    saida.push('\\');
                }
                barras = 0;
                saida.push('\\');
                saida.push('"');
            }
            outro => {
                barras = 0;
                saida.push(outro);
            }
        }
    }
    for _ in 0..barras {
        saida.push('\\');
    }
    saida.push('"');
    saida
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nome_de_pipe_tem_entropia_e_prefixo() {
        let a = nome_de_pipe_aleatorio().unwrap();
        let b = nome_de_pipe_aleatorio().unwrap();
        assert!(a.starts_with("rse-"));
        assert_eq!(a.len(), 4 + 32, "128 bits em hexadecimal");
        assert_ne!(a, b, "dois nomes seguidos nao podem coincidir");
    }

    #[test]
    fn citar_preserva_argumento_simples() {
        assert_eq!(citar_para_shell("1sak1"), "1sak1");
        assert_eq!(citar_para_shell("--pipe"), "--pipe");
    }

    #[test]
    fn citar_protege_caminho_com_espaco() {
        assert_eq!(
            citar_para_shell(r"D:\DEV Ragnarok\jogo.exe"),
            r#""D:\DEV Ragnarok\jogo.exe""#
        );
    }

    #[test]
    fn citar_dobra_barra_no_fim() {
        // Sem dobrar, a aspa de fechamento seria escapada e o proximo argumento
        // entraria dentro deste.
        assert_eq!(citar_para_shell(r"C:\Com Espaco\"), r#""C:\Com Espaco\\""#);
    }
}
