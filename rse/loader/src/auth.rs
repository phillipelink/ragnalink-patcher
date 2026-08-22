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
//! O Loader manda o SHA-256 do executavel do jogo. Nesta fase e informativo: o
//! servidor registra, nao decide nada com ele. A partir da Fase 5 e a DLL quem
//! calcula, ja de dentro do processo, e ai vira material de decisao.

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
}

fn enforce_log() -> String {
    "log".to_string()
}

impl Politica {
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

/// SHA-256 do executavel do jogo, em hexadecimal.
pub fn hash_do_cliente(exe: &Path) -> Result<String> {
    let bytes = std::fs::read(exe)
        .with_context(|| format!("nao consegui ler {} para calcular o hash", exe.display()))?;
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
    fn hash_do_cliente_e_o_sha256_do_arquivo() {
        let dir = std::env::temp_dir().join("rse-loader-teste-hash");
        std::fs::create_dir_all(&dir).unwrap();
        let arq = dir.join("falso.exe");
        std::fs::write(&arq, b"abc").unwrap();

        // SHA-256 de "abc", o vetor mais conhecido do FIPS 180-4.
        assert_eq!(
            hash_do_cliente(&arq).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&arq);
    }

    #[test]
    fn hash_do_cliente_explica_arquivo_ausente() {
        let e = hash_do_cliente(Path::new("/nao/existe/mesmo.exe")).unwrap_err();
        assert!(format!("{}", e).contains("nao consegui ler"));
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
