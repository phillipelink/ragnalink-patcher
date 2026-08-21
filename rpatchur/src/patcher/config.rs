use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use super::get_patcher_name;
use anyhow::{Context, Result};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Clone)]
pub struct PatcherConfiguration {
    pub window: WindowConfiguration,
    pub play: PlayConfiguration,
    pub setup: SetupConfiguration,
    pub web: WebConfiguration,
    pub client: ClientConfiguration,
    pub patching: PatchingConfiguration,
}

#[derive(Deserialize, Clone)]
pub struct WindowConfiguration {
    pub title: String,
    pub width: i32,
    pub height: i32,
    pub resizable: bool,
    /// Remove a barra de titulo do Windows. `Option` de proposito: configuracoes
    /// antigas, sem este campo, continuam validas e caem no `false`.
    ///
    /// ATENCAO: sem a barra somem tambem o fechar, o minimizar e o ARRASTAR. A
    /// interface precisa oferecer os tres - ver os comandos "exit", "minimize" e
    /// "drag" em ui.rs. Ligar isto com uma pagina que nao os implemente deixa a
    /// janela presa na tela, sem como mover nem fechar.
    pub frameless: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct PlayConfiguration {
    pub path: String,
    pub arguments: Vec<String>,
    pub exit_on_success: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct SetupConfiguration {
    pub path: String,
    pub arguments: Vec<String>,
    pub exit_on_success: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct WebConfiguration {
    /// Onde esta a interface. Aceita duas formas:
    ///   - caminho RELATIVO (ex.: `patcher/index.html`), resolvido a partir da
    ///     pasta do executavel. E a forma recomendada para distribuir.
    ///   - endereco completo com esquema (`https://...` ou `file:///...`),
    ///     usado como esta.
    pub index_url: String,
    /// A MESMA pagina hospedada no site, usada so como rede de seguranca quando
    /// o arquivo local nao existe. Opcional.
    pub index_url_remoto: Option<String>,
    pub preferred_patch_server: Option<String>, // Name of the patch server to use in priority
    pub patch_servers: Vec<PatchServerInfo>,
}

#[derive(Deserialize, Clone)]
pub struct PatchServerInfo {
    pub name: String,      // Name of that identifies the patch server
    pub plist_url: String, // URL of the plist.txt file
    pub patch_url: String, // URL of the directory containing .thor files
}

#[derive(Deserialize, Clone)]
pub struct ClientConfiguration {
    pub default_grf_name: String, // GRF file to patch by default
}

#[derive(Deserialize, Clone)]
pub struct PatchingConfiguration {
    pub in_place: bool,        // In-place GRF patching
    pub check_integrity: bool, // Check THOR archives' integrity
    pub create_grf: bool,      // Create new GRFs if they don't exist
}

pub fn retrieve_patcher_configuration(
    config_file_path: Option<PathBuf>,
) -> Result<PatcherConfiguration> {
    let patcher_name = get_patcher_name()?;
    // Use given configuration path if present
    let config_file_path =
        config_file_path.unwrap_or_else(|| PathBuf::from(patcher_name).with_extension("yml"));
    // Read the YAML content of the file as an instance of `PatcherConfiguration`.
    let mut config = parse_configuration(config_file_path)?;
    config.web.index_url = resolver_index_url(
        &config.web.index_url,
        config.web.index_url_remoto.as_deref(),
    )?;
    Ok(config)
}

/// Transforma o `index_url` da configuracao num endereco que funcione na maquina
/// de quem esta rodando.
///
/// 🚨 POR QUE ISTO EXISTE, e por que nao pode ser removido:
/// o yml distribuido trazia um caminho ABSOLUTO da maquina de desenvolvimento -
/// `file:///E:/DEV%20Ragnarok/ClienteRagnaLinK/patcher/index.html`. Na maquina de
/// qualquer outra pessoa esse caminho nao existe, o MSHTML nao carrega pagina
/// nenhuma e - como a janela roda SEM barra de titulo - o jogador ve um
/// retangulo vazio e conclui que o programa "nao abriu". Aconteceu num teste
/// real, na casa de um amigo, e do lado dele nao havia como descobrir a causa.
///
/// Agora o yml traz um caminho RELATIVO e ele e resolvido a partir da pasta do
/// EXECUTAVEL. O cliente passa a funcionar instalado em qualquer lugar, sem
/// ninguem editar arquivo de configuracao.
///
/// Valor com esquema (`https://`, `file://`) continua respeitado como esta, pra
/// nao quebrar quem aponta de proposito pra pagina hospedada no site.
fn resolver_index_url(bruto: &str, remoto: Option<&str>) -> Result<String> {
    if bruto.contains("://") {
        return Ok(bruto.to_owned());
    }

    let base = env::current_exe()?
        .parent()
        .context("Could not determine the patcher's own directory")?
        .to_path_buf();
    // Barra invertida do Windows vira barra normal: assim tanto
    // `patcher\index.html` quanto `patcher/index.html` funcionam no yml.
    let caminho = base.join(bruto.replace('\\', "/"));

    if !caminho.is_file() {
        // Interface local faltando. Abrir uma janela em branco e o pior desfecho
        // possivel: nao ha mensagem, nao ha barra de titulo, nao ha o que
        // clicar. Se houver copia hospedada configurada, usa ela e o jogador
        // sequer percebe.
        if let Some(r) = remoto {
            log::error!(
                "UI file not found at '{}'; falling back to '{}'",
                caminho.display(),
                r
            );
            return Ok(r.to_owned());
        }
        log::error!(
            "UI file not found at '{}' and no 'index_url_remoto' configured; \
             the window will come up blank",
            caminho.display()
        );
    }

    // Url::from_file_path cuida do que da errado quando se monta o endereco a
    // mao: espaco, acento e a barra do Windows. O caminho da instalacao pode
    // perfeitamente ter os tres.
    match Url::from_file_path(&caminho) {
        Ok(u) => Ok(u.to_string()),
        Err(_) => Err(anyhow::anyhow!(
            "Invalid UI path: '{}'",
            caminho.display()
        )),
    }
}

fn parse_configuration(config_file_path: impl AsRef<Path>) -> Result<PatcherConfiguration> {
    let config_file = File::open(config_file_path)?;
    let config_reader = BufReader::new(config_file);
    serde_yaml::from_reader(config_reader).context("Invalid configuration")
}
