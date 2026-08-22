//! Configuracao que o Loader entrega a DLL no momento da injecao.
//!
//! # Como ela chega la, e por que assim
//!
//! Ao contrario da credencial launcher->Loader (que vai por named pipe, ver
//! `handover`), esta config e escrita **diretamente na memoria do processo do
//! jogo** durante a injecao: o Loader faz `VirtualAllocEx` + `WriteProcessMemory`
//! e passa o endereco para a funcao `rse_configure` exportada pela DLL.
//!
//! O motivo e que aqui ha um segredo de verdade - a `K_s`, chave de sessao do
//! canal cifrado. Ela **nao pode** ir por:
//!
//! - **linha de comando**: DLL nao tem argv, e de todo modo seria publica;
//! - **variavel de ambiente**: o bloco de ambiente do processo e legivel por
//!   qualquer processo do mesmo usuario com `ReadProcessMemory`, e aparece em
//!   ferramentas como o Process Explorer;
//! - **secao nomeada** (`CreateFileMapping` com nome): o nome seria adivinhavel,
//!   e uma janela de corrida permitiria outro processo abrir a secao primeiro.
//!
//! Escrever numa regiao anonima do processo alvo, cujo endereco so o Loader
//! conhece e so e passado pela `CreateRemoteThread`, fecha essas tres portas.
//!
//! # Uma honestidade sobre o modelo de ameaca
//!
//! Isto NAO torna a `K_s` inextraivel. A DLL vive dentro do Ragexe, que e
//! exatamente o processo que um atacante controla - quem consegue executar
//! codigo la dentro le a `K_s` da memoria da DLL de qualquer jeito. O canal
//! cifrado e o cuidado com a entrega sao **defesa em profundidade**: elevam o
//! custo e barram o bisbilhoteiro externo. A garantia forte de que um cliente
//! adulterado nao entra continua sendo a validacao do ticket no login-server,
//! com a `K_ticket` que nunca sai do servidor.
//!
//! # Formato
//!
//! ```text
//! offset  tam  campo
//!      0    4  magic "RSED"
//!      4    1  versao (= DLL_CONFIG_VERSION)
//!      5    1  tamanho do nome do pipe
//!      6   32  K_s (chave de sessao)
//!     38   16  session_id
//!     54    N  nome do pipe, ASCII
//! ```
//!
//! Tamanho fixo de 54 bytes de cabecalho + o nome do pipe. O Loader gera um
//! blob deste, o escreve no alvo, e a DLL o le de volta.

use crate::crypto::Key;
use crate::error::DllConfigError;
use crate::version::{KEY_LEN, SESSION_ID_LEN};

/// Marca do blob de configuracao. Distinta de `TICKET_MAGIC` (`RSE1`) e de
/// `HANDOVER_MAGIC` (`RSEH`).
pub const DLL_CONFIG_MAGIC: [u8; 4] = *b"RSED";

/// Versao do formato. Loader e DLL sao do mesmo lancamento, sempre casados.
pub const DLL_CONFIG_VERSION: u8 = 1;

/// magic(4) + versao(1) + tam_pipe(1) + K_s(32) + session_id(16) = 54.
pub const DLL_CONFIG_HEADER_LEN: usize = 6 + KEY_LEN + SESSION_ID_LEN;

/// Teto do nome do pipe. Nomes do RSE sao `rse-dll-<32 hex>` ~ 40 bytes.
pub const DLL_CONFIG_MAX_PIPE: usize = 128;

/// Config ja interpretada, pronta para uso pela DLL.
///
/// Deriva `Zeroize` no `Key`, entao a `K_s` e limpa da memoria quando esta
/// estrutura sai de escopo. O `parse` devolve isto por valor de proposito: o
/// blob cru deve ser zerado pelo chamador logo apos, e a chave vive so aqui.
// Sem `Debug` de proposito: esta struct carrega a K_s, e um `{:?}` que a
// imprimisse por acidente vazaria a chave para um log. O `frame::Key` ja e
// redigido no Debug; aqui a defesa e simplesmente nao derivar.
#[allow(missing_debug_implementations)]
pub struct DllConfig {
    pub pipe_name: String,
    pub session_key: Key,
    pub session_id: [u8; SESSION_ID_LEN],
}

/// Monta o blob que o Loader escreve no processo do jogo.
pub fn serialize(
    pipe_name: &str,
    session_key: &Key,
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<Vec<u8>, DllConfigError> {
    let nome = pipe_name.as_bytes();
    if nome.is_empty() {
        return Err(DllConfigError::EmptyPipe);
    }
    if nome.len() > DLL_CONFIG_MAX_PIPE {
        return Err(DllConfigError::PipeTooLong);
    }

    let mut out = Vec::with_capacity(DLL_CONFIG_HEADER_LEN + nome.len());
    out.extend_from_slice(&DLL_CONFIG_MAGIC);
    out.push(DLL_CONFIG_VERSION);
    out.push(nome.len() as u8);
    out.extend_from_slice(session_key.as_bytes());
    out.extend_from_slice(session_id);
    out.extend_from_slice(nome);
    Ok(out)
}

/// Interpreta o blob lido da memoria do processo.
pub fn parse(buf: &[u8]) -> Result<DllConfig, DllConfigError> {
    if buf.len() < DLL_CONFIG_HEADER_LEN {
        return Err(DllConfigError::Truncated);
    }
    if buf[0..4] != DLL_CONFIG_MAGIC {
        return Err(DllConfigError::BadMagic);
    }
    if buf[4] != DLL_CONFIG_VERSION {
        return Err(DllConfigError::BadVersion);
    }

    let tam_pipe = buf[5] as usize;
    if tam_pipe == 0 {
        return Err(DllConfigError::EmptyPipe);
    }
    if tam_pipe > DLL_CONFIG_MAX_PIPE {
        return Err(DllConfigError::PipeTooLong);
    }

    let fim = DLL_CONFIG_HEADER_LEN + tam_pipe;
    if buf.len() < fim {
        return Err(DllConfigError::Truncated);
    }

    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&buf[6..6 + KEY_LEN]);
    let mut sid = [0u8; SESSION_ID_LEN];
    sid.copy_from_slice(&buf[6 + KEY_LEN..DLL_CONFIG_HEADER_LEN]);

    let pipe_name = std::str::from_utf8(&buf[DLL_CONFIG_HEADER_LEN..fim])
        .map_err(|_| DllConfigError::PipeNotUtf8)?
        .to_string();

    Ok(DllConfig {
        pipe_name,
        session_key: Key::from_bytes(k),
        session_id: sid,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn cfg() -> (String, Key, [u8; SESSION_ID_LEN]) {
        (
            "rse-dll-00112233445566778899aabbccddeeff".to_string(),
            Key::from_bytes([7u8; KEY_LEN]),
            [0x5a; SESSION_ID_LEN],
        )
    }

    #[test]
    fn ida_e_volta() {
        let (pipe, k, sid) = cfg();
        let blob = serialize(&pipe, &k, &sid).unwrap();
        let lido = parse(&blob).unwrap();
        assert_eq!(lido.pipe_name, pipe);
        assert_eq!(lido.session_key.as_bytes(), k.as_bytes());
        assert_eq!(lido.session_id, sid);
    }

    #[test]
    fn cabecalho_tem_o_tamanho_documentado() {
        let (pipe, k, sid) = cfg();
        let blob = serialize(&pipe, &k, &sid).unwrap();
        assert_eq!(blob.len(), DLL_CONFIG_HEADER_LEN + pipe.len());
        assert_eq!(&blob[0..4], b"RSED");
        assert_eq!(DLL_CONFIG_HEADER_LEN, 54);
    }

    #[test]
    fn pipe_vazio_reprova_nas_duas_pontas() {
        let (_, k, sid) = cfg();
        assert!(matches!(serialize("", &k, &sid), Err(DllConfigError::EmptyPipe)));
    }

    #[test]
    fn pipe_longo_demais_reprova() {
        let (_, k, sid) = cfg();
        let gigante = "a".repeat(DLL_CONFIG_MAX_PIPE + 1);
        assert!(matches!(serialize(&gigante, &k, &sid), Err(DllConfigError::PipeTooLong)));
    }

    #[test]
    fn magic_errado_reprova() {
        let (pipe, k, sid) = cfg();
        let mut blob = serialize(&pipe, &k, &sid).unwrap();
        blob[0] = b'X';
        assert!(matches!(parse(&blob), Err(DllConfigError::BadMagic)));
    }

    #[test]
    fn versao_errada_reprova() {
        let (pipe, k, sid) = cfg();
        let mut blob = serialize(&pipe, &k, &sid).unwrap();
        blob[4] = DLL_CONFIG_VERSION + 1;
        assert!(matches!(parse(&blob), Err(DllConfigError::BadVersion)));
    }

    #[test]
    fn truncado_reprova() {
        let (pipe, k, sid) = cfg();
        let blob = serialize(&pipe, &k, &sid).unwrap();
        for corte in 0..blob.len() {
            assert!(parse(&blob[..corte]).is_err(), "corte em {}", corte);
        }
    }

    #[test]
    fn pipe_nao_ascii_reprova() {
        let (_, k, sid) = cfg();
        // Monta um blob a mao com bytes invalidos no nome do pipe.
        let mut blob = Vec::new();
        blob.extend_from_slice(&DLL_CONFIG_MAGIC);
        blob.push(DLL_CONFIG_VERSION);
        blob.push(2);
        blob.extend_from_slice(k.as_bytes());
        blob.extend_from_slice(&sid);
        blob.extend_from_slice(&[0xFF, 0xFE]);
        assert!(matches!(parse(&blob), Err(DllConfigError::PipeNotUtf8)));
    }

    /// A `K_s` do blob, uma vez derivada, tem que gerar exatamente as mesmas
    /// chaves de canal que o Loader gerou. E o que garante que os dois lados
    /// conseguem se falar depois da injecao.
    #[test]
    fn a_chave_derivada_bate_com_a_do_loader() {
        use crate::crypto::derive_channel_keys;
        let (pipe, k, sid) = cfg();
        let blob = serialize(&pipe, &k, &sid).unwrap();
        let lido = parse(&blob).unwrap();

        let (l2d_loader, d2l_loader) = derive_channel_keys(&k, &sid);
        let (l2d_dll, d2l_dll) = derive_channel_keys(&lido.session_key, &lido.session_id);

        assert_eq!(l2d_loader.as_bytes(), l2d_dll.as_bytes());
        assert_eq!(d2l_loader.as_bytes(), d2l_dll.as_bytes());
    }
}
