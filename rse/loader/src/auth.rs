//! Conversa com o RSE Auth Service.
//!
//! O Loader faz dois tipos de pedido: troca a credencial de sessao por um ticket
//! de 30 s (`/ticket`), e consulta a politica (`/policy`) para o kill-switch —
//! no arranque, antes de injetar, e a cada 60 s enquanto o jogo roda. O envio de
//! violacoes (`/report`) entra na Fase 5c, quando a DLL tiver o que reportar.
//!
//! # Sobre o TLS
//!
//! O `reqwest` no Windows usa o schannel, ou seja, o proprio TLS do sistema.
//! Isso importa por dois motivos praticos: o repositorio de certificados e o do
//! Windows (empresas com proxy de inspecao continuam funcionando) e as
//! configuracoes de proxy do usuario sao respeitadas sem codigo nenhum. Um
//! cliente TLS proprio, com raizes embutidas, quebraria nos dois casos - e o
//! jogador nao teria como descobrir o motivo.
//!
//! # Sobre o `client_hash`
//!
//! O Loader manda o SHA-256 do **manifesto de integridade** (RSE_SPEC §7), que
//! por sua vez cobre o executavel e as GRFs. Enquanto a lista de manifestos
//! aceitos do Auth Service estiver vazia, ele so registra; preenchida, ela passa
//! a barrar cliente cujo conjunto de arquivos o servidor nao reconhece.

use anyhow::{anyhow, bail, Context, Result};
use rse_protocol::crypto::{sha256, to_hex};
use rse_protocol::version::{RSE_PROTOCOL, TICKET_LEN};
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

/// Prazo do pedido de ticket.
///
/// Curto de proposito: o jogador esta olhando para o launcher esperando o jogo
/// abrir. Se o Auth Service nao respondeu em 8 s, ele nao vai responder - e uma
/// mensagem de erro rapida e melhor do que um minuto de tela parada.
const TIMEOUT_HTTP: Duration = Duration::from_secs(8);

pub struct Ticket {
    /// Os 148 bytes que o login-server vai conferir.
    pub bytes: Vec<u8>,
    pub key_id: u8,
    pub expira_em_ms: u32,
}

#[derive(Deserialize)]
struct RespostaTicket {
    ticket: String,
    #[serde(default)]
    expires_in_ms: u32,
    #[serde(default)]
    key_id: u8,
}

#[derive(Deserialize)]
struct RespostaErro {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// Junta a base com o caminho sem duplicar nem comer a barra.
fn juntar(base: &str, caminho: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), caminho.trim_start_matches('/'))
}

/// A politica corrente do Auth Service — o que o kill-switch lê.
#[derive(Deserialize)]
pub struct Politica {
    /// Estado de enforcement: `"off"` | `"log"` | `"on"`. `"off"` é o freio de
    /// emergência: o login-server para de exigir ticket **e** o Loader para de
    /// injetar. `"log"`/`"on"` mantêm o Loader injetando.
    #[serde(default = "enforce_log")]
    pub enforce: String,
    #[serde(default)]
    pub policy_epoch: u32,
    /// Quantos clientes o mesmo computador pode ter abertos ao mesmo tempo.
    /// `0` (o padrão, e o que um servidor antigo devolve por omissão) = sem
    /// limite. Vem do servidor de propósito: mudar o limite não deve exigir
    /// redistribuir cliente.
    #[serde(default)]
    pub max_clients: u32,
}

fn enforce_log() -> String {
    "log".to_string()
}

impl Politica {
    /// A política que vale quando o servidor não pôde ser consultado: proteção
    /// ligada (`log`) e **sem** limite de clientes. Um soluço de rede não pode
    /// desligar o RSE nem trancar o jogador fora.
    pub fn padrao() -> Politica {
        Politica {
            enforce: enforce_log(),
            policy_epoch: 0,
            max_clients: 0,
        }
    }

    /// O Loader deve recuar (abrir o jogo **sem** injetar) quando a política está
    /// em `"off"`. É o kill-switch: um `"off"` explícito de um serviço no ar
    /// desliga o RSE do lado cliente sem redistribuir binário.
    ///
    /// Campo ausente ou valor estranho cai no default `"log"` — um JSON malformado
    /// **nunca** vira kill-switch por acidente. Desligar exige um `"off"` claro.
    pub fn loader_desligado(&self) -> bool {
        self.enforce.eq_ignore_ascii_case("off")
    }
}

/// Consulta `GET /policy`. Usada pelo kill-switch, no arranque e a cada 60 s.
pub fn consultar_politica(base_url: &str) -> Result<Politica> {
    let url = juntar(base_url, "policy");

    let cliente = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT_HTTP)
        .build()
        .context("nao consegui montar o cliente HTTP")?;

    let resposta = cliente
        .get(&url)
        .send()
        .with_context(|| format!("nao consegui falar com o Auth Service em {}", url))?;

    let status = resposta.status();
    let texto = resposta.text().unwrap_or_default();
    if !status.is_success() {
        bail!("o Auth Service recusou a consulta de politica (HTTP {})", status);
    }

    serde_json::from_str::<Politica>(&texto)
        .with_context(|| format!("resposta de /policy nao e o JSON esperado: {}", texto))
}

/// Traduz uma falha do Loader para uma frase que o **jogador** entenda.
///
/// # Por que isto existe
///
/// Em release o Loader não tem console, e o launcher já fechou quando ele roda.
/// Sem esta tradução, qualquer falha vira **silêncio**: o jogador clica em
/// JOGAR, vê a telinha aparecer e sumir, e nada acontece. Ele clica de novo, e
/// de novo, e abre um chamado dizendo "o jogo não abre" — sem nenhuma
/// informação que ajude, e achando que o problema é do servidor.
///
/// Um anti-cheat que barra sem explicar **transfere para o suporte** o custo de
/// cada bloqueio que ele faz. E o caso mais importante é justamente o do cliente
/// modificado: essa pessoa merece saber que o problema está nos arquivos dela, e
/// que a solução é deixar o launcher atualizar.
///
/// A classificação é por texto do erro. É frágil por natureza, então cada caso
/// tem teste, e o fallback nunca é vazio: no pior caso o jogador recebe uma
/// mensagem genérica **e** o caminho do log, que é melhor do que nada.
pub fn explicar(erro: &anyhow::Error) -> String {
    let t = format!("{:#}", erro);

    // Do mais específico para o mais genérico.
    if t.contains("CLIENT_HASH_UNKNOWN") {
        return "Os arquivos do seu cliente estão diferentes dos publicados pelo \
                servidor.\n\nAbra o launcher e deixe a atualização terminar antes de \
                jogar. Se você modificou algum arquivo do jogo, restaure a versão \
                original."
            .to_string();
    }
    if t.contains("LAUNCHER_UNKNOWN") {
        return "Esta versão do launcher não é mais aceita pelo servidor.\n\n\
                Baixe a versão mais recente no site do RagnaLinK."
            .to_string();
    }
    if t.contains("SESSION_REVOKED") {
        return "Sua sessão foi encerrada pelo servidor.\n\nAbra o launcher e \
                tente de novo. Se continuar, fale com o suporte."
            .to_string();
    }
    if t.contains("CREDENTIAL_EXPIRED") || t.contains("BAD_CREDENTIAL") {
        return "A sessão expirou antes do jogo abrir.\n\nIsso costuma acontecer \
                quando o launcher fica aberto por muito tempo. Feche e abra o \
                launcher, e clique em JOGAR de novo."
            .to_string();
    }
    if t.contains("RATE_LIMITED") {
        return "Muitas tentativas seguidas.\n\nEspere um minuto e tente de novo."
            .to_string();
    }
    // Rede: o jogador não tem o que consertar no cliente, e a orientação é outra.
    if t.contains("nao consegui falar com o Auth Service") {
        return "Não foi possível falar com o servidor de autenticação.\n\n\
                Verifique sua conexão com a internet. Se ela estiver boa, o \
                servidor pode estar em manutenção — tente de novo em alguns \
                minutos."
            .to_string();
    }
    if t.contains("nao recebi a credencial") {
        return "O launcher não conseguiu conversar com a proteção.\n\n\
                Feche o launcher e abra de novo. Se persistir, seu antivírus pode \
                estar bloqueando o RagnaShield."
            .to_string();
    }
    if t.contains("injecao da DLL falhou") {
        return "A proteção não conseguiu iniciar.\n\nSeu antivírus pode estar \
                bloqueando o RagnaShield. Tente adicionar a pasta do jogo às \
                exceções e abrir de novo."
            .to_string();
    }
    if t.contains("CLIENTE_DESATUALIZADO") {
        return "O executável do jogo está desatualizado.\n\nAbra o launcher e \
                deixe a atualização terminar — a versão nova não pede mais \
                permissão de administrador para abrir."
            .to_string();
    }
    if t.contains("nao encontrei") || t.contains("nao consegui criar o processo") {
        return "Não foi possível abrir o cliente do jogo.\n\nAlgum arquivo pode \
                estar faltando. Abra o launcher e deixe a atualização terminar."
            .to_string();
    }

    // Desconhecido: mensagem honesta, sem inventar diagnóstico.
    format!(
        "A proteção não conseguiu iniciar o jogo.\n\nDetalhe técnico:\n{}\n\n\
         Se precisar de suporte, envie o arquivo rse_loader.log que está na pasta \
         do jogo.",
        t
    )
}

/// Uma violação vinda da DLL, pronta para o `/report`.
pub struct Violacao {
    pub code: u32,
    pub severity: String,
    pub detail: String,
}

/// `POST /report` — repassa as violações da DLL ao Auth Service e devolve a
/// **ação** que ele decidiu (o REPORT_ACK): hoje sempre `"report"` (modo
/// telemetria), mas o Loader já obedece o que vier. Falha de rede devolve
/// `"report"` — na Fase 5c-1 nada é fatal, é só medição.
pub fn reportar(base_url: &str, credencial: &str, violacoes: &[Violacao]) -> Result<String> {
    let url = juntar(base_url, "report");

    let cliente = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT_HTTP)
        .build()
        .context("nao consegui montar o cliente HTTP")?;

    let corpo = serde_json::json!({
        "protocol": RSE_PROTOCOL,
        "sessionCredential": credencial,
        "violations": violacoes
            .iter()
            .map(|v| serde_json::json!({
                "code": v.code, "severity": v.severity, "detail": v.detail
            }))
            .collect::<Vec<_>>(),
    });

    let resposta = cliente
        .post(&url)
        .json(&corpo)
        .send()
        .with_context(|| format!("nao consegui falar com o Auth Service em {}", url))?;

    let status = resposta.status();
    let texto = resposta.text().unwrap_or_default();
    if !status.is_success() {
        bail!("o Auth Service recusou o /report (HTTP {})", status);
    }

    #[derive(Deserialize)]
    struct RespostaReport {
        #[serde(default)]
        action: String,
    }
    let r: RespostaReport = serde_json::from_str(&texto).unwrap_or(RespostaReport {
        action: String::new(),
    });
    Ok(if r.action.is_empty() {
        "report".to_string()
    } else {
        r.action
    })
}

/// SHA-256 do **manifesto de integridade**, em hexadecimal — o `client_hash` do
/// ticket (bytes 84–116), como o RSE_SPEC §7 define.
///
/// # Por que o manifesto, e nao o `.exe`
///
/// Ate a Fase 5c-2a este campo levava o SHA do executavel do jogo — era o que
/// dava, porque manifesto nao existia. Agora existe, e o manifesto **cobre** o
/// executavel (o hash dele e uma linha la dentro) mais as GRFs. Um unico numero
/// passa a resumir o cliente inteiro, que e o que permite ao Auth Service
/// decidir se aquele conjunto de arquivos e um cliente que ele reconhece.
///
/// # O que este numero passa a valer (e o que ainda nao vale)
///
/// Enquanto a lista de manifestos aceitos do Auth Service estiver **vazia**, ele
/// so registra — e a integridade continua sendo deteccao de adulteracao casual,
/// porque quem edita a GRF pode regerar o manifesto e mandar o hash novo. O
/// numero passa a **barrar** quando a lista for preenchida com os manifestos que
/// voce publicou: dai um manifesto regerado pelo jogador nao esta na lista, o
/// ticket nao e emitido, e sem ticket nao ha login.
///
/// Ausente ou ilegivel devolve zeros — que e um valor honesto e distinguivel:
/// "este cliente nao tem manifesto" nao e a mesma coisa que "tem um manifesto
/// que nao reconheco".
pub const NOME_MANIFESTO: &str = "rse_manifest.txt";

pub fn hash_do_manifesto(exe: &Path) -> Result<String> {
    let manifesto = exe
        .parent()
        .map(|d| d.join(NOME_MANIFESTO))
        .ok_or_else(|| anyhow!("o caminho do jogo nao tem pasta pai"))?;
    let bytes = std::fs::read(&manifesto)
        .with_context(|| format!("nao consegui ler {}", manifesto.display()))?;
    Ok(to_hex(&sha256(&bytes)))
}

pub fn pedir_ticket_com_hash(base_url: &str, credencial: &str, client_hash: &str) -> Result<Ticket> {
    let url = juntar(base_url, "ticket");

    let cliente = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT_HTTP)
        .build()
        .context("nao consegui montar o cliente HTTP")?;

    let corpo = serde_json::json!({
        "protocol": RSE_PROTOCOL,
        "sessionCredential": credencial,
        "clientHash": client_hash,
    });

    let resposta = cliente
        .post(&url)
        .json(&corpo)
        .send()
        .with_context(|| format!("nao consegui falar com o Auth Service em {}", url))?;

    let status = resposta.status();
    let texto = resposta.text().unwrap_or_default();

    if !status.is_success() {
        // O corpo de erro do Auth Service e {error, message}. Repassar os dois
        // e o que permite o suporte distinguir CREDENTIAL_EXPIRED (o jogador
        // deixou o launcher aberto a noite toda) de RATE_LIMITED (outra coisa
        // esta errada) sem precisar de acesso ao servidor.
        let detalhe = serde_json::from_str::<RespostaErro>(&texto)
            .map(|e| format!("{}: {}", e.error, e.message))
            .unwrap_or_else(|_| texto.trim().to_string());
        bail!("o Auth Service recusou o ticket (HTTP {}) — {}", status, detalhe);
    }

    let r: RespostaTicket = serde_json::from_str(&texto)
        .with_context(|| format!("resposta do Auth Service nao e o JSON esperado: {}", texto))?;

    let bytes = de_base64(&r.ticket)
        .ok_or_else(|| anyhow!("o campo `ticket` nao e base64 valido"))?;

    if bytes.len() != TICKET_LEN {
        bail!(
            "ticket com {} bytes, esperado {}. Auth Service e Loader estao em \
             versoes diferentes do protocolo?",
            bytes.len(),
            TICKET_LEN
        );
    }

    Ok(Ticket {
        bytes,
        key_id: r.key_id,
        expira_em_ms: r.expires_in_ms,
    })
}

/// Base64 padrao -> bytes.
///
/// Escrito a mao pelo mesmo motivo do `rse-smoke`: sao 25 linhas, e a
/// alternativa e mais um crate no executavel que vai para o jogador.
fn de_base64(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut valor = [255u8; 256];
    for (i, c) in T.iter().enumerate() {
        valor[*c as usize] = i as u8;
    }

    let mut saida = Vec::new();
    let mut acumulador: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = valor[c as usize];
        if v == 255 {
            return None;
        }
        acumulador = (acumulador << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            saida.push((acumulador >> bits) as u8);
        }
    }
    Some(saida)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn juntar_normaliza_as_barras() {
        assert_eq!(juntar("https://x/rse/v1", "ticket"), "https://x/rse/v1/ticket");
        assert_eq!(juntar("https://x/rse/v1/", "ticket"), "https://x/rse/v1/ticket");
        assert_eq!(juntar("https://x/rse/v1", "/ticket"), "https://x/rse/v1/ticket");
        assert_eq!(juntar("https://x/rse/v1/", "/ticket"), "https://x/rse/v1/ticket");
    }

    #[test]
    fn base64_ida_e_volta() {
        // Vetores do RFC 4648, que e onde o formato esta definido.
        assert_eq!(de_base64("").unwrap(), b"");
        assert_eq!(de_base64("Zg==").unwrap(), b"f");
        assert_eq!(de_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(de_base64("Zm9v").unwrap(), b"foo");
        assert_eq!(de_base64("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn base64_recusa_caractere_invalido() {
        assert!(de_base64("Zm9v!").is_none());
        assert!(de_base64("###").is_none());
    }

    #[test]
    fn hash_do_manifesto_e_o_sha256_do_manifesto_ao_lado_do_exe() {
        let dir = std::env::temp_dir().join("rse-loader-teste-manifesto");
        std::fs::create_dir_all(&dir).unwrap();
        let arq = dir.join("falso.exe");
        std::fs::write(&arq, b"o conteudo do exe NAO entra na conta").unwrap();
        std::fs::write(dir.join(NOME_MANIFESTO), b"abc").unwrap();

        // SHA-256 de "abc", o vetor mais conhecido do FIPS 180-4 — provando que
        // o que foi hasheado e o MANIFESTO, e nao o executavel ao lado dele.
        assert_eq!(
            hash_do_manifesto(&arq).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&arq);
        let _ = std::fs::remove_file(dir.join(NOME_MANIFESTO));
    }

    #[test]
    fn hash_do_manifesto_explica_manifesto_ausente() {
        let dir = std::env::temp_dir().join("rse-loader-teste-sem-manifesto");
        std::fs::create_dir_all(&dir).unwrap();
        let arq = dir.join("falso.exe");
        std::fs::write(&arq, b"x").unwrap();
        let e = hash_do_manifesto(&arq).unwrap_err();
        assert!(format!("{}", e).contains("nao consegui ler"));
        let _ = std::fs::remove_file(&arq);
    }

    #[test]
    fn politica_off_liga_o_kill_switch() {
        let p: Politica = serde_json::from_str(r#"{"enforce":"off","policy_epoch":3}"#).unwrap();
        assert!(p.loader_desligado());
        assert_eq!(p.policy_epoch, 3);
    }

    #[test]
    fn politica_off_ignora_caixa() {
        for j in [r#"{"enforce":"OFF"}"#, r#"{"enforce":"Off"}"#] {
            let p: Politica = serde_json::from_str(j).unwrap();
            assert!(p.loader_desligado(), "{} deveria desligar", j);
        }
    }

    #[test]
    fn politica_log_e_on_mantem_a_protecao() {
        // Inclui um valor estranho de propósito: só "off" exato desliga.
        for j in [r#"{"enforce":"log"}"#, r#"{"enforce":"on"}"#, r#"{"enforce":"official"}"#] {
            let p: Politica = serde_json::from_str(j).unwrap();
            assert!(!p.loader_desligado(), "{} NAO deveria desligar", j);
        }
    }

    #[test]
    fn politica_sem_campo_enforce_nao_desliga() {
        // Campo ausente cai no default "log" — JSON malformado nunca vira kill-switch.
        let p: Politica = serde_json::from_str(r#"{"policy_epoch":1}"#).unwrap();
        assert!(!p.loader_desligado());
        assert_eq!(p.enforce, "log");
    }
}
