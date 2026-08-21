//! Erros do protocolo.
//!
//! Todos os erros sao `enum` sem `String` de proposito. Tres motivos:
//!
//!  1. O login-server precisa converter isto num codigo numerico de log. Texto
//!     livre viraria parse de string.
//!  2. Mensagem de erro montada em tempo de execucao aloca - e este crate roda
//!     dentro do processo do jogo.
//!  3. Erro de cripto nao deve contar ao adversario ONDE falhou com mais
//!     detalhe do que o necessario.

use core::fmt;

/// Falhas na validacao de um ticket.
///
/// A ordem dos codigos numericos e parte do formato de log: o login-server
/// grava `rse_reject=<codigo>`. Nao renumere, so acrescente no fim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TicketError {
    /// Nao tem 148 bytes.
    InvalidLength = 1,
    /// Nao comeca com "RSE1".
    BadMagic = 2,
    /// Versao do protocolo fora da janela aceita.
    BadVersion = 3,
    /// `key_id` que o verificador nao conhece.
    UnknownKey = 4,
    /// HMAC nao confere. Ticket forjado, corrompido, ou chave errada.
    BadSignature = 5,
    /// Passou do `issued_at + ttl`.
    Expired = 6,
    /// `issued_at` no futuro alem da tolerancia de relogio.
    NotYetValid = 7,
    /// `nonce` ja foi usado. Alguem esta reenviando um ticket capturado.
    Replay = 8,
    /// `ttl_ms` zero ou acima do teto.
    BadTtl = 9,
}

impl TicketError {
    /// Codigo numerico estavel, para log e telemetria.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Rotulo curto e estavel. Usado no log do servidor e nos vetores de teste;
    /// o lado C++ compara contra exatamente estes textos.
    pub fn label(self) -> &'static str {
        match self {
            TicketError::InvalidLength => "INVALID_LENGTH",
            TicketError::BadMagic => "BAD_MAGIC",
            TicketError::BadVersion => "BAD_VERSION",
            TicketError::UnknownKey => "UNKNOWN_KEY",
            TicketError::BadSignature => "BAD_SIGNATURE",
            TicketError::Expired => "EXPIRED",
            TicketError::NotYetValid => "FUTURE",
            TicketError::Replay => "REPLAY",
            TicketError::BadTtl => "BAD_TTL",
        }
    }
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl std::error::Error for TicketError {}

/// Falhas no canal Loader <-> DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameError {
    /// Bytes insuficientes para um frame completo.
    Truncated = 101,
    /// Nao comeca com "RS".
    BadMagic = 102,
    /// Versao do protocolo diferente.
    BadVersion = 103,
    /// `payload_len` acima de `FRAME_MAX_PAYLOAD`.
    PayloadTooLarge = 104,
    /// AEAD recusou: chave errada, nonce errado, ou bytes adulterados.
    ///
    /// Deliberadamente um erro so. Distinguir "tag errada" de "cabecalho
    /// adulterado" entregaria informacao de graca a quem esta sondando.
    Decrypt = 105,
    /// `seq` menor ou igual ao ultimo visto nesta direcao: replay ou reordenacao.
    ReplayedSequence = 106,
    /// Contador de 32 bits estourou. A sessao precisa recomecar com chave nova.
    SequenceExhausted = 107,
    /// Opcode fora da tabela.
    ///
    /// Quem RECEBE isto deve registrar e IGNORAR o frame - nunca derrubar a
    /// conexao. E o que permite adicionar opcode novo sem quebrar quem ainda
    /// nao atualizou.
    UnknownOpcode = 108,
}

impl FrameError {
    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn label(self) -> &'static str {
        match self {
            FrameError::Truncated => "TRUNCATED",
            FrameError::BadMagic => "BAD_MAGIC",
            FrameError::BadVersion => "BAD_VERSION",
            FrameError::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            FrameError::Decrypt => "DECRYPT",
            FrameError::ReplayedSequence => "REPLAYED_SEQUENCE",
            FrameError::SequenceExhausted => "SEQUENCE_EXHAUSTED",
            FrameError::UnknownOpcode => "UNKNOWN_OPCODE",
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl std::error::Error for FrameError {}

/// Falha ao obter entropia do sistema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomError;

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RANDOM_UNAVAILABLE")
    }
}

impl std::error::Error for RandomError {}

#[cfg(test)]
// Em teste, `expect` e `assert` sao a ferramenta certa.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Os codigos numericos e os rotulos sao FORMATO, nao detalhe interno: o
    /// login-server grava `rse_reject=<codigo>` e os vetores comparam contra o
    /// rotulo. Renumerar quebra painel, alerta e o lado C++ ao mesmo tempo.
    #[test]
    fn codigos_e_rotulos_de_ticket_estao_congelados() {
        let esperado: [(TicketError, u16, &str); 9] = [
            (TicketError::InvalidLength, 1, "INVALID_LENGTH"),
            (TicketError::BadMagic, 2, "BAD_MAGIC"),
            (TicketError::BadVersion, 3, "BAD_VERSION"),
            (TicketError::UnknownKey, 4, "UNKNOWN_KEY"),
            (TicketError::BadSignature, 5, "BAD_SIGNATURE"),
            (TicketError::Expired, 6, "EXPIRED"),
            (TicketError::NotYetValid, 7, "FUTURE"),
            (TicketError::Replay, 8, "REPLAY"),
            (TicketError::BadTtl, 9, "BAD_TTL"),
        ];
        for (e, codigo, rotulo) in esperado {
            assert_eq!(e.code(), codigo, "codigo de {:?}", e);
            assert_eq!(e.label(), rotulo, "rotulo de {:?}", e);
            assert_eq!(format!("{}", e), rotulo);
        }
    }

    #[test]
    fn codigos_e_rotulos_de_frame_estao_congelados() {
        let esperado: [(FrameError, u16, &str); 8] = [
            (FrameError::Truncated, 101, "TRUNCATED"),
            (FrameError::BadMagic, 102, "BAD_MAGIC"),
            (FrameError::BadVersion, 103, "BAD_VERSION"),
            (FrameError::PayloadTooLarge, 104, "PAYLOAD_TOO_LARGE"),
            (FrameError::Decrypt, 105, "DECRYPT"),
            (FrameError::ReplayedSequence, 106, "REPLAYED_SEQUENCE"),
            (FrameError::SequenceExhausted, 107, "SEQUENCE_EXHAUSTED"),
            (FrameError::UnknownOpcode, 108, "UNKNOWN_OPCODE"),
        ];
        for (e, codigo, rotulo) in esperado {
            assert_eq!(e.code(), codigo, "codigo de {:?}", e);
            assert_eq!(e.label(), rotulo, "rotulo de {:?}", e);
            assert_eq!(format!("{}", e), rotulo);
        }
    }

    /// Ticket e frame usam faixas separadas (1..99 e 101..199) para que um
    /// codigo em log nunca seja ambiguo.
    #[test]
    fn as_faixas_de_codigo_nao_se_cruzam() {
        assert!(TicketError::BadTtl.code() < 100);
        assert!(FrameError::Truncated.code() > 100);
    }

    #[test]
    fn erro_de_entropia_tem_rotulo() {
        assert_eq!(format!("{}", RandomError), "RANDOM_UNAVAILABLE");
    }

    #[test]
    fn implementam_std_error() {
        fn aceita(_: &dyn std::error::Error) {}
        aceita(&TicketError::Expired);
        aceita(&FrameError::Decrypt);
        aceita(&RandomError);
    }
}
