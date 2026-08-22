//! Entrega da credencial de sessao do launcher para o Loader.
//!
//! # Por que isto existe, e por que nao e o canal do `frame.rs`
//!
//! Sao dois canais diferentes, com ameacas diferentes:
//!
//! | | launcher -> Loader (aqui) | Loader <-> DLL (`frame.rs`) |
//! |---|---|---|
//! | Quantas mensagens | **uma**, no arranque | milhares, durante toda a partida |
//! | Quem esta do outro lado | processo que o launcher acabou de criar | processo hospedeiro do jogo, potencialmente hostil |
//! | Cifrado | **nao** | sim, AES-256-GCM |
//!
//! O canal do `frame.rs` e cifrado porque a DLL vive dentro do Ragexe, que e
//! exatamente o processo que o atacante controla. Aqui nao ha esse problema: a
//! credencial anda entre dois processos do mesmo usuario, por um named pipe cuja
//! DACL so admite esse usuario, e a leitura acontece em menos de um segundo.
//!
//! Cifrar assim mesmo pareceria mais seguro e **seria pior**: a chave teria que
//! chegar ao Loader de alguma forma, e o unico caminho disponivel seria a linha
//! de comando - que e precisamente o lugar de onde estamos tirando a credencial.
//! Trocaria um segredo exposto por outro, com uma camada a mais para auditar.
//!
//! # Por que nao o handle herdado (ADR-004 original)
//!
//! Herdar handle exige `CreateProcess` com `bInheritHandles = TRUE`. O launcher
//! precisa criar o Loader com `ShellExecuteExW` e verbo `runas`, porque o Ragexe
//! roda elevado hoje e o Loader tem que estar no MESMO nivel de integridade para
//! conseguir injetar a DLL na Fase 5. E o `ShellExecuteExW` nao herda handles.
//!
//! Ou seja: elevacao e handle herdado sao mutuamente exclusivos nessas APIs. O
//! pipe atende os dois objetivos - some da linha de comando E atravessa a
//! fronteira de elevacao (a politica obrigatoria do Windows e *no-write-up*:
//! integridade alta abre objeto criado por integridade media).
//!
//! # Formato
//!
//! ```text
//! offset  tam  campo
//!      0    4  magic "RSEH"
//!      4    1  versao do handover (= HANDOVER_VERSION)
//!      5    2  tamanho da credencial, big-endian
//!      7    N  credencial, UTF-8, sem terminador
//! ```
//!
//! Big-endian pelo mesmo motivo do ticket: o formato e de rede, e a escolha
//! sendo uniforme no projeto inteiro elimina uma classe de engano.

use crate::error::HandoverError;

/// Marca do quadro de handover. Nao confundir com `TICKET_MAGIC` (`RSE1`).
pub const HANDOVER_MAGIC: [u8; 4] = *b"RSEH";

/// Versao do formato de handover.
///
/// Independente do `RSE_PROTOCOL`: este canal e interno ao par
/// launcher/Loader, que sao distribuidos juntos e sempre na mesma versao.
pub const HANDOVER_VERSION: u8 = 1;

/// Cabecalho: magic(4) + versao(1) + tamanho(2).
pub const HANDOVER_HEADER_LEN: usize = 7;

/// Teto do tamanho da credencial.
///
/// A credencial real do Auth Service tem por volta de 180 caracteres. O teto
/// existe para que um cliente de pipe torto nao consiga fazer o Loader alocar
/// um buffer grande - e para que o Loader possa ler o cabecalho, conferir, e so
/// entao ler o resto.
pub const HANDOVER_MAX_CREDENTIAL: usize = 4096;

/// Serializa a credencial para envio pelo pipe. Usado pelo launcher.
pub fn serialize(credencial: &str) -> Result<Vec<u8>, HandoverError> {
    let bytes = credencial.as_bytes();
    if bytes.is_empty() {
        return Err(HandoverError::Empty);
    }
    if bytes.len() > HANDOVER_MAX_CREDENTIAL {
        return Err(HandoverError::TooLong);
    }

    let mut saida = Vec::with_capacity(HANDOVER_HEADER_LEN + bytes.len());
    saida.extend_from_slice(&HANDOVER_MAGIC);
    saida.push(HANDOVER_VERSION);
    saida.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    saida.extend_from_slice(bytes);
    Ok(saida)
}

/// Le o cabecalho e devolve quantos bytes de credencial ainda faltam ler.
///
/// Separado do [`parse`] de proposito: quem le de um pipe nao sabe de antemao
/// quanto vai chegar. O padrao de uso e ler exatamente
/// [`HANDOVER_HEADER_LEN`] bytes, chamar isto, e so entao ler o restante.
pub fn parse_header(buf: &[u8]) -> Result<usize, HandoverError> {
    if buf.len() < HANDOVER_HEADER_LEN {
        return Err(HandoverError::Truncated);
    }
    if buf[0..4] != HANDOVER_MAGIC {
        return Err(HandoverError::BadMagic);
    }
    if buf[4] != HANDOVER_VERSION {
        return Err(HandoverError::BadVersion);
    }

    let tam = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    if tam == 0 {
        return Err(HandoverError::Empty);
    }
    if tam > HANDOVER_MAX_CREDENTIAL {
        return Err(HandoverError::TooLong);
    }
    Ok(tam)
}

/// Interpreta um quadro completo. Usado pelo Loader.
///
/// A credencial precisa ser UTF-8 valido: ela vai direto para um cabecalho HTTP
/// depois, e um erro aqui e melhor do que um pedido malformado la.
pub fn parse(buf: &[u8]) -> Result<String, HandoverError> {
    let tam = parse_header(buf)?;
    let fim = HANDOVER_HEADER_LEN + tam;

    if buf.len() < fim {
        return Err(HandoverError::Truncated);
    }
    // Bytes sobrando sao recusados: num canal de UMA mensagem, lixo depois do
    // fim significa que alguem esta escrevendo coisa que nao devia.
    if buf.len() > fim {
        return Err(HandoverError::TrailingBytes);
    }

    String::from_utf8(buf[HANDOVER_HEADER_LEN..fim].to_vec())
        .map_err(|_| HandoverError::NotUtf8)
}

#[cfg(test)]
// Em teste, `unwrap` e `assert` sao a ferramenta certa.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const CRED: &str = "v1.abcdef0123456789.MEUHMACAQUI==";

    #[test]
    fn ida_e_volta() {
        let quadro = serialize(CRED).unwrap();
        assert_eq!(parse(&quadro).unwrap(), CRED);
    }

    #[test]
    fn cabecalho_tem_o_tamanho_documentado() {
        let quadro = serialize(CRED).unwrap();
        assert_eq!(quadro.len(), HANDOVER_HEADER_LEN + CRED.len());
        assert_eq!(&quadro[0..4], b"RSEH");
        assert_eq!(quadro[4], HANDOVER_VERSION);
    }

    #[test]
    fn parse_header_devolve_o_que_falta_ler() {
        let quadro = serialize(CRED).unwrap();
        let faltam = parse_header(&quadro[..HANDOVER_HEADER_LEN]).unwrap();
        assert_eq!(faltam, CRED.len());
    }

    #[test]
    fn credencial_vazia_reprova_nas_duas_pontas() {
        assert!(matches!(serialize(""), Err(HandoverError::Empty)));

        let mut torto = Vec::from(HANDOVER_MAGIC);
        torto.push(HANDOVER_VERSION);
        torto.extend_from_slice(&0u16.to_be_bytes());
        assert!(matches!(parse_header(&torto), Err(HandoverError::Empty)));
    }

    #[test]
    fn credencial_longa_demais_reprova() {
        let gigante = "a".repeat(HANDOVER_MAX_CREDENTIAL + 1);
        assert!(matches!(serialize(&gigante), Err(HandoverError::TooLong)));
    }

    #[test]
    fn magic_errado_reprova() {
        let mut quadro = serialize(CRED).unwrap();
        quadro[0] = b'X';
        assert!(matches!(parse(&quadro), Err(HandoverError::BadMagic)));
    }

    #[test]
    fn versao_errada_reprova() {
        let mut quadro = serialize(CRED).unwrap();
        quadro[4] = HANDOVER_VERSION + 1;
        assert!(matches!(parse(&quadro), Err(HandoverError::BadVersion)));
    }

    #[test]
    fn truncado_reprova_em_qualquer_ponto() {
        let quadro = serialize(CRED).unwrap();
        for corte in 0..quadro.len() {
            assert!(
                parse(&quadro[..corte]).is_err(),
                "cortado em {} deveria reprovar",
                corte
            );
        }
    }

    #[test]
    fn bytes_sobrando_reprovam() {
        let mut quadro = serialize(CRED).unwrap();
        quadro.push(0);
        assert!(matches!(parse(&quadro), Err(HandoverError::TrailingBytes)));
    }

    #[test]
    fn nao_utf8_reprova() {
        let mut quadro = Vec::from(HANDOVER_MAGIC);
        quadro.push(HANDOVER_VERSION);
        quadro.extend_from_slice(&2u16.to_be_bytes());
        quadro.extend_from_slice(&[0xFF, 0xFE]); // sequencia invalida
        assert!(matches!(parse(&quadro), Err(HandoverError::NotUtf8)));
    }

    #[test]
    fn credencial_no_limite_exato_passa() {
        let no_limite = "a".repeat(HANDOVER_MAX_CREDENTIAL);
        let quadro = serialize(&no_limite).unwrap();
        assert_eq!(parse(&quadro).unwrap(), no_limite);
    }
}
