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
        "machineHint": maquina::impressao(),
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
//  Impressao de maquina
// ===========================================================================

/// O `machine_hint` que vai no `POST /session`.
///
/// # Por que isto existe (e por que quase custou caro)
///
/// Ate agosto/2026 esta funcao nao existia: o launcher mandava `"0" * 64` fixo,
/// porque **nada dependia da impressao ainda**. O campo estava no protocolo desde
/// a Fase 2, atravessava o ticket, e ninguem olhava para ele.
///
/// Quando a espera por maquina entrou (a consequencia do `kill`), esse zero
/// virou uma bomba: como todos os jogadores mandavam a MESMA impressao, todos
/// ficavam com a MESMA `machine_fp` no servidor — e uma unica deteccao num unico
/// jogador poria o servidor inteiro de castigo. Um trapaceiro derrubaria o
/// servidor de proposito em trinta segundos.
///
/// O servidor tem um fusivel para isso (reconhece a impressao coringa e se recusa
/// a aplicar espera sobre ela). Esta funcao e o outro lado: enquanto o jogador
/// estiver com launcher que manda zero, a espera nao vale para ele.
///
/// # O que entra no hash — e por que exatamente isto
///
/// A formula esta no **RSE_SPEC §8** e nao foi inventada aqui:
///
/// ```text
/// machine_fp = SHA-256( pepper_do_servidor || volume_serial || machine_guid || cpu_id )
/// ```
///
/// Este lado calcula `SHA-256(volume_serial || machine_guid || cpu_id)`; o pepper
/// entra no servidor, onde ele mora.
///
/// | Fonte | O que e | Estabilidade |
/// |---|---|---|
/// | `volume_serial` | numero sorteado na formatacao do disco do sistema | muda ao formatar |
/// | `machine_guid`  | GUID que o Windows gera na instalacao | muda ao reinstalar o Windows |
/// | `cpu_id`        | fabricante + familia/modelo do processador | muda ao trocar de CPU |
///
/// O `cpu_id` identifica o **modelo**, nao a peca: milhares de jogadores com o
/// mesmo processador contribuem com os mesmos bytes. Ele entra para desempatar
/// duas maquinas que por acaso coincidissem nas outras fontes, nao como
/// identidade.
///
/// O que o spec **proibe** e respeitado aqui: nada de MAC de placa de rede (muda
/// com VPN, Wi-Fi x cabo, dock USB) e nada de nome de usuario do Windows. A
/// espera e por MAQUINA — num PC de familia ela pega a casa, e essa e a semantica
/// pretendida, nao um efeito colateral.
///
/// # Privacidade (RSE_SPEC §8)
///
/// O que sai da maquina do jogador e **so o SHA-256**, nunca os valores crus. O
/// servidor ainda tempera com a `RSE_PEPPER` antes de guardar, de modo que nem um
/// vazamento do lado de la permite correlacionar com um hardware conhecido. Os
/// valores crus tambem nao vao para log nenhum.
///
/// # Limites, ditos em voz alta
///
/// - **Formatar o disco ou reinstalar o Windows muda a impressao.** Para uma
///   espera de minutos isso e irrelevante; para banimento nao seria — e mais um
///   motivo para banir ser decisao humana, e nao automatica.
/// - **E forjavel** por quem sabe o que esta fazendo: e um valor que o cliente
///   calcula e envia. Serve para tornar a volta chata, nao para deter um
///   adversario determinado.
/// - Se **nenhuma** fonte responder, devolvemos a coringa de zeros de proposito:
///   e melhor a espera nao valer para essa maquina do que ela colidir com todas
///   as outras maquinas que tambem falharam.
#[cfg(windows)]
mod maquina {
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::minwindef::{DWORD, HKEY};
    use winapi::um::fileapi::GetVolumeInformationW;
    use winapi::um::winnt::{KEY_READ, KEY_WOW64_64KEY, REG_SZ};
    use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE};

    /// Impressao da maquina, em hex de 64 caracteres.
    ///
    /// Ver o cabecalho da secao para a formula e os limites.
    pub fn impressao() -> String {
        let mut partes: Vec<String> = Vec::new();

        if let Some(serial) = serial_do_volume_do_sistema() {
            partes.push(format!("vol:{:08X}", serial));
        }
        if let Some(guid) = machine_guid() {
            partes.push(format!("guid:{}", guid));
        }
        if let Some(cpu) = cpu_id() {
            partes.push(format!("cpu:{}", cpu));
        }

        if partes.is_empty() {
            // Ver "Limites" no cabecalho: coringa deliberada, nao improviso.
            return "0".repeat(64);
        }

        // Prefixo de dominio: o mesmo material nunca deve produzir o mesmo hash
        // em dois usos diferentes do protocolo.
        let material = format!("RSE1 machine-hint\n{}", partes.join("\n"));
        rse_protocol::crypto::to_hex(&rse_protocol::crypto::sha256(material.as_bytes()))
    }

    fn para_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Serial do volume onde o Windows esta instalado.
    ///
    /// Usa `%SystemDrive%` e nao `C:` fixo: instalacao em outra letra existe, e e
    /// melhor cair no ramo "nao sei" do que medir o disco errado.
    fn serial_do_volume_do_sistema() -> Option<u32> {
        let drive = std::env::var("SystemDrive").ok()?;
        let raiz = para_wide(&format!("{}\\", drive.trim_end_matches('\\')));

        let mut serial: DWORD = 0;
        // SAFETY: `raiz` e NUL-terminada e vive ate o fim da chamada; os demais
        // ponteiros de saida sao nulos, que a API aceita como "nao quero isso".
        let ok = unsafe {
            GetVolumeInformationW(
                raiz.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };

        if ok == 0 || serial == 0 {
            None
        } else {
            Some(serial)
        }
    }

    /// `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
    ///
    /// # A pegadinha do `KEY_WOW64_64KEY`
    ///
    /// O launcher e **32 bits** (tem que ser: a DLL precisa da mesma arquitetura
    /// do Ragexe). Num Windows 64 bits, um processo 32 bits que abre
    /// `HKLM\SOFTWARE\...` e desviado para `WOW6432Node` — que tem um MachineGuid
    /// DIFERENTE do canonico.
    ///
    /// Sem `KEY_WOW64_64KEY`, a impressao mudaria se um dia o launcher virasse 64
    /// bits, e nao bateria com a de qualquer outra ferramenta que leia o valor
    /// normal. Uma linha aqui evita uma diferenca que so apareceria muito depois,
    /// e sem explicacao obvia.
    fn machine_guid() -> Option<String> {
        let caminho = para_wide("SOFTWARE\\Microsoft\\Cryptography");
        let nome = para_wide("MachineGuid");
        let mut chave: HKEY = std::ptr::null_mut();

        // SAFETY: `caminho` e NUL-terminada; `chave` recebe a saida.
        let r = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                caminho.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut chave,
            )
        };
        // A API devolve LSTATUS; 0 e ERROR_SUCCESS. Comparado com 0 direto para
        // nao precisar da feature `winerror` do winapi so por uma constante.
        if r != 0 {
            return None;
        }

        let mut tipo: DWORD = 0;
        let mut bytes: Vec<u8> = vec![0; 256];
        let mut tam: DWORD = bytes.len() as DWORD;

        // SAFETY: chave aberta acima; `bytes` e nosso e `tam` diz o tamanho real.
        let r = unsafe {
            RegQueryValueExW(
                chave,
                nome.as_ptr(),
                std::ptr::null_mut(),
                &mut tipo,
                bytes.as_mut_ptr(),
                &mut tam,
            )
        };
        // SAFETY: handle valido, e ninguem mais o usa depois daqui.
        unsafe { RegCloseKey(chave) };

        if r != 0 || tipo != REG_SZ || tam == 0 {
            return None;
        }

        // O valor e UTF-16. `tam` esta em BYTES, e inclui o NUL final.
        let u16s: Vec<u16> = bytes[..tam as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();

        let s = String::from_utf16_lossy(&u16s);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Fabricante + familia/modelo/stepping do processador, via `CPUID`.
    ///
    /// # O bit que estraga tudo se ninguem reparar
    ///
    /// O `EBX` da folha 1 carrega o **APIC ID inicial**, que depende de QUAL
    /// nucleo executou a instrucao. Incluir esse registrador faria a impressao
    /// mudar entre execucoes na mesma maquina — o tipo de instabilidade que so
    /// aparece em campo, como "a espera as vezes nao pega". Por isso a folha 1
    /// entra sem o `EBX`.
    ///
    /// A folha 0 (string do fabricante) e constante e entra inteira.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn cpu_id() -> Option<String> {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::__cpuid;

        // SAFETY: CPUID existe em qualquer x86 desde o 486; folhas 0 e 1 sao as
        // mais basicas e sempre suportadas.
        let (f0, f1) = unsafe { (__cpuid(0), __cpuid(1)) };

        Some(format!(
            "{:08X}{:08X}{:08X}-{:08X}{:08X}{:08X}",
            f0.ebx, f0.edx, f0.ecx, f1.eax, f1.ecx, f1.edx
        ))
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn cpu_id() -> Option<String> {
        None
    }
}

/// Fora do Windows nao ha o que medir — e o launcher so roda em Windows de
/// verdade. Existe para o `cargo check` continuar valendo em qualquer maquina.
#[cfg(not(windows))]
mod maquina {
    pub fn impressao() -> String {
        "0".repeat(64)
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
