//! Constantes do protocolo e regras de compatibilidade.
//!
//! Tudo que e "numero magico" do RSE mora aqui. Se um valor aparece em dois
//! lugares do codigo, ele esta errado num deles - e a chance de descobrir isso
//! e no dia do lancamento.

/// Versao do protocolo. Vai no ticket (byte 4), no frame do pipe (byte 2) e no
/// corpo das requisicoes HTTP.
///
/// REGRA DE INCREMENTO (docs/RSE_SPEC.md, secao 10):
///   - campo novo em espaco reservado, opcode novo, campo JSON novo -> NAO muda
///   - layout do ticket, semantica de campo, primitiva de cripto -> incrementa
///
/// Incrementar isto obriga o login-server a aceitar N e N-1 durante a janela de
/// migracao, senao todo mundo que ainda nao atualizou o cliente para de entrar.
pub const RSE_PROTOCOL: u8 = 1;

// ---------------------------------------------------------------------------
//  Ticket
// ---------------------------------------------------------------------------

/// Assinatura do ticket: ASCII "RSE1".
pub const TICKET_MAGIC: [u8; 4] = *b"RSE1";

/// Tamanho total do ticket serializado.
pub const TICKET_LEN: usize = 148;

/// Quantos bytes do inicio entram no HMAC. O restante (32 bytes) E o HMAC.
pub const TICKET_SIGNED_LEN: usize = 116;

/// Tamanho do HMAC-SHA256.
pub const MAC_LEN: usize = 32;

/// Validade padrao do ticket.
///
/// 30 s parece pouco, e e de proposito: o ticket e pedido no instante em que o
/// jogador aperta "Conectar", nao na abertura do launcher. Entre o pedido e a
/// chegada no login-server passam milissegundos. 30 s cobre latencia ruim,
/// relogio torto e um retry - e deixa uma janela curtissima pra quem capturar o
/// pacote tentar reusar.
pub const TICKET_DEFAULT_TTL_MS: u32 = 30_000;

/// Tolerancia para relogio adiantado no cliente.
///
/// Sem isto, uma maquina com o relogio 2 s a frente emitiria tickets que o
/// servidor leria como "vindos do futuro" e recusaria - e o jogador nao teria
/// como saber o porque.
pub const TICKET_CLOCK_SKEW_MS: u64 = 5_000;

/// Teto de TTL aceito na validacao.
///
/// Existe pra que um bug (ou um Auth Service comprometido) nao consiga emitir
/// ticket com validade de um ano. O verificador recusa antes mesmo de olhar o
/// relogio.
pub const TICKET_MAX_TTL_MS: u32 = 120_000;

// Deslocamentos dentro do ticket. Big-endian, conforme docs/RSE_SPEC.md 4.1.
// Publicos de proposito: fazem parte do FORMATO, e quem for portar a leitura
// para C++ (Fase 3) ou inspecionar um ticket em log precisa deles.
pub const OFF_MAGIC: usize = 0;
pub const OFF_VERSION: usize = 4;
pub const OFF_FLAGS: usize = 5;
pub const OFF_KEY_ID: usize = 6;
pub const OFF_RESERVED: usize = 7;
pub const OFF_ISSUED_AT: usize = 8;
pub const OFF_TTL: usize = 16;
pub const OFF_NONCE: usize = 20;
pub const OFF_SESSION_ID: usize = 36;
pub const OFF_MACHINE_FP: usize = 52;
pub const OFF_CLIENT_HASH: usize = 84;
pub const OFF_HMAC: usize = 116;

// ---------------------------------------------------------------------------
//  Packet do login-server
// ---------------------------------------------------------------------------

/// Header do packet que leva o ticket ate o login-server.
///
/// Escolhido apos conferir que 0x0AAA nao e usado em lugar nenhum do rAthena -
/// nem na build de dez/2023 do RagnaLinK, nem no master atual. O `switch` do
/// `logclif_parse` cai no `default` e derruba a conexao para packets
/// desconhecidos, entao adicionar um `case` e a mudanca minima possivel.
///
/// O 0x0825 (CA_SSO_LOGIN_REQ) foi descartado: o rAthena limita o token dele a
/// NAME_LENGTH-1 = 23 bytes e o trata como senha. Um ticket com HMAC-256 nao
/// cabe em 23 bytes (ver ADR-007).
pub const LOGIN_PACKET_ID: u16 = 0x0AAA;

/// Tamanho total do packet 0x0AAA: header(2) + tamanho(2) + ticket(148).
pub const LOGIN_PACKET_LEN: usize = 4 + TICKET_LEN;

// ---------------------------------------------------------------------------
//  Frame do canal Loader <-> DLL
// ---------------------------------------------------------------------------

pub const FRAME_MAGIC: [u8; 2] = *b"RS";

/// Cabecalho do frame: magic(2) version(1) opcode(1) seq(4) len(2) flags(2) nonce(12).
pub const FRAME_HEADER_LEN: usize = 24;

/// Parte do cabecalho que entra como AAD do AES-GCM (tudo antes do nonce).
pub const FRAME_AAD_LEN: usize = 12;

/// Tag do AES-GCM.
pub const FRAME_TAG_LEN: usize = 16;

/// Teto do payload de um frame.
///
/// Frame nao e canal de transferencia de arquivo. Um relatorio de violacao que
/// nao cabe em 8 KiB e relatorio mal formatado - e aceitar tamanho arbitrario e
/// convite para alguem do outro lado pedir alocacao de 4 GiB.
pub const FRAME_MAX_PAYLOAD: usize = 8192;

/// Intervalo do heartbeat da DLL para o Loader.
pub const HEARTBEAT_INTERVAL_MS: u32 = 5_000;

/// Prazo para o Loader responder o heartbeat.
pub const HEARTBEAT_ACK_TIMEOUT_MS: u32 = 2_000;

/// Quantos heartbeats podem ser perdidos antes de derrubar a sessao.
pub const HEARTBEAT_MAX_MISSES: u32 = 3;

/// Prazo do HELLO_ACK depois da injecao.
///
/// Estourou: o Loader mata o processo suspenso. NUNCA dar ResumeThread sem
/// confirmacao - cliente retomado sem DLL e exatamente o que se quer evitar.
pub const HANDSHAKE_TIMEOUT_MS: u32 = 5_000;

// ---------------------------------------------------------------------------
//  Chaves
// ---------------------------------------------------------------------------

/// Tamanho de todas as chaves simetricas do RSE.
pub const KEY_LEN: usize = 32;

pub const SESSION_ID_LEN: usize = 16;
pub const TICKET_NONCE_LEN: usize = 16;
pub const FINGERPRINT_LEN: usize = 32;

/// Rotulos do HKDF. Mudar qualquer um destes textos quebra a compatibilidade
/// com quem ja esta em campo - trate como parte do formato, nao como string.
pub const HKDF_INFO_L2D: &[u8] = b"RSE1 loader->dll";
pub const HKDF_INFO_D2L: &[u8] = b"RSE1 dll->loader";

/// Saleiro do nonce do AES-GCM, por direcao.
///
/// O nonce e `salt(4) || contador(8)`. Direcoes diferentes usam saleiros
/// diferentes para que, mesmo num erro de derivacao que fizesse as duas pontas
/// compartilharem chave, o par (chave, nonce) nunca se repita. Repetir nonce em
/// GCM nao "enfraquece um pouco": destroi a confidencialidade e permite forjar
/// mensagem. Vale o cinto e o suspensorio.
pub const NONCE_SALT_L2D: [u8; 4] = *b"L2D\0";
pub const NONCE_SALT_D2L: [u8; 4] = *b"D2L\0";

/// Aceita a versao lida de um campo `version`.
///
/// Aceitamos N e N-1 de proposito: durante uma migracao existem clientes das
/// duas versoes em campo ao mesmo tempo, e recusar a anterior seria o mesmo que
/// desligar o servidor para metade dos jogadores.
#[inline]
pub fn version_supported(v: u8) -> bool {
    v == RSE_PROTOCOL || (RSE_PROTOCOL > 1 && v == RSE_PROTOCOL - 1)
}

#[cfg(test)]
// Em teste, `expect` e `assert` sao a ferramenta certa: falha de teste DEVE
// abortar com mensagem. A proibicao de panico vale para o codigo que roda
// dentro do processo do jogo, nao para o que roda no CI.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn layout_do_ticket_fecha() {
        // Se alguem mexer num offset sem mexer no tamanho, isto quebra aqui e
        // nao em producao.
        assert_eq!(OFF_HMAC, TICKET_SIGNED_LEN);
        assert_eq!(OFF_HMAC + MAC_LEN, TICKET_LEN);
        assert_eq!(OFF_ISSUED_AT + 8, OFF_TTL);
        assert_eq!(OFF_TTL + 4, OFF_NONCE);
        assert_eq!(OFF_NONCE + TICKET_NONCE_LEN, OFF_SESSION_ID);
        assert_eq!(OFF_SESSION_ID + SESSION_ID_LEN, OFF_MACHINE_FP);
        assert_eq!(OFF_MACHINE_FP + FINGERPRINT_LEN, OFF_CLIENT_HASH);
        assert_eq!(OFF_CLIENT_HASH + 32, OFF_HMAC);
    }

    #[test]
    fn layout_do_frame_fecha() {
        assert_eq!(FRAME_AAD_LEN + 12, FRAME_HEADER_LEN);
    }

    #[test]
    fn versao_atual_e_aceita() {
        assert!(version_supported(RSE_PROTOCOL));
        assert!(!version_supported(RSE_PROTOCOL + 1));
        assert!(!version_supported(0));
    }
}
