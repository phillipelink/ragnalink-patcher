//! Reconhecimento dos packets de login do cliente — a inteligência do netgate,
//! em formato puro e testável.
//!
//! # Por que isto mora aqui, e não na DLL
//!
//! O netgate (Fase 5b) intercepta o `send` do Ragexe e precisa decidir, olhando
//! os bytes que saem, se aquilo é o packet de login — o momento de antepor o
//! `0x0AAA`. Essa decisão é lógica pura: dado um buffer, qual o opcode, e ele é
//! um pedido de login? Mantê-la aqui, longe do `unsafe` do hook, é o que permite
//! testá-la byte a byte sem um Windows e um Ragexe rodando.
//!
//! # Os opcodes
//!
//! Conferidos contra `src/common/packets.hpp` do emulador em uso (rAthena de
//! abr/2026, `PACKETVER 20211103`). São os `CA_LOGIN*` que o `logclif` registra
//! no `PacketDatabase`. Se o cliente usar um que não está aqui, o netgate NÃO
//! antepõe — e é por isso que ele também registra o opcode visto, para o caso
//! virar uma linha de correção em vez de um mistério.

/// Os opcodes de **pedido de login** que o login-server aceita.
///
/// A ordem não importa; é uma tabela de consulta. Todos disparam o
/// `login_mmo_auth` no servidor, que é onde o ticket do RSE é conferido — então
/// o `0x0AAA` tem que preceder qualquer um deles na conexão.
pub const OPCODES_LOGIN: [u16; 7] = [
    0x0064, // CA_LOGIN
    0x01dd, // CA_LOGIN2
    0x01fa, // CA_LOGIN3
    0x0277, // CA_LOGIN_PCBANG
    0x027c, // CA_LOGIN4
    0x02b0, // CA_LOGIN_CHANNEL
    0x0825, // CA_SSO_LOGIN_REQ
];

/// Nosso próprio packet. Se já estiver saindo, NÃO anteponha de novo — evita o
/// laço em que o hook interceptaria o `0x0AAA` que ele mesmo mandou.
pub const OPCODE_RSE: u16 = 0x0AAA;

/// Lê o opcode (2 bytes, little-endian, como todo packet RO) do começo do buffer.
///
/// `None` se o buffer é curto demais para ter cabeçalho.
pub fn opcode_de(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([buf[0], buf[1]]))
}

/// É um pedido de login? — a pergunta que o netgate faz a cada `send`.
pub fn eh_pedido_de_login(opcode: u16) -> bool {
    OPCODES_LOGIN.contains(&opcode)
}

/// O buffer que sai começa com um pedido de login?
///
/// É esta a condição para antepor o `0x0AAA`. Repare que ela é falsa para o
/// próprio `0x0AAA` e para os packets de pré-login (hash check, req hash), que
/// passam intactos.
pub fn buffer_eh_login(buf: &[u8]) -> bool {
    matches!(opcode_de(buf), Some(op) if eh_pedido_de_login(op))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf_com_opcode(op: u16) -> Vec<u8> {
        let mut v = op.to_le_bytes().to_vec();
        v.extend_from_slice(&[0u8; 53]); // corpo qualquer, como um 0x0064 de 55 B
        v
    }

    #[test]
    fn reconhece_todos_os_opcodes_de_login() {
        for op in OPCODES_LOGIN {
            assert!(eh_pedido_de_login(op), "0x{:04x} deveria ser login", op);
            assert!(buffer_eh_login(&buf_com_opcode(op)));
        }
    }

    #[test]
    fn o_0064_classico_e_login() {
        // O caso que o rse-smoke monta e que o cliente classico manda.
        assert!(buffer_eh_login(&buf_com_opcode(0x0064)));
    }

    #[test]
    fn o_proprio_0aaa_nao_e_login() {
        // Se fosse, o hook anteporia um 0x0AAA antes do 0x0AAA, em laco.
        assert!(!eh_pedido_de_login(OPCODE_RSE));
        assert!(!buffer_eh_login(&buf_com_opcode(OPCODE_RSE)));
    }

    #[test]
    fn packets_de_pre_login_nao_disparam() {
        // Estes chegam ANTES do login na mesma conexao e devem passar intactos.
        for op in [0x01db_u16 /*REQ_HASH*/, 0x0200 /*CONNECT_INFO*/, 0x0204 /*EXE_HASH*/] {
            assert!(!eh_pedido_de_login(op), "0x{:04x} nao e login", op);
        }
    }

    #[test]
    fn opcode_le_little_endian() {
        // 0x0064 na fita e 0x64 0x00.
        assert_eq!(opcode_de(&[0x64, 0x00]), Some(0x0064));
        assert_eq!(opcode_de(&[0xAA, 0x0A]), Some(0x0AAA));
    }

    #[test]
    fn buffer_curto_nao_tem_opcode() {
        assert_eq!(opcode_de(&[]), None);
        assert_eq!(opcode_de(&[0x64]), None);
        assert!(!buffer_eh_login(&[0x64]));
    }
}
