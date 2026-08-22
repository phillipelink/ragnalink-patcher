//! Cargas (payloads) das mensagens do canal, em formato puro e testavel.
//!
//! O frame — magic, seq, cifra, tag — e do `rse_protocol::frame`. Aqui fica so o
//! CONTEUDO de cada opcode, que e o que a DLL e o Loader precisam concordar byte
//! a byte. Manter isto fora do modulo com FFI e o que permite testar o formato
//! em qualquer maquina, sem Windows.
//!
//! Alguns leitores (`ler_*`) so serao usados pelo lado do Loader e pela Fase 5b;
//! ficam aqui, testados, para as duas pontas lerem do MESMO codigo. O
//! `allow(dead_code)` cobre o que ainda nao tem chamador neste crate.
#![allow(dead_code)]

/// Payload do `HELLO_ACK` (DLL -> Loader): a DLL se apresenta.
///
/// ```text
/// offset  tam  campo
///      0    1  versao do protocolo
///      1    4  PID do processo do jogo (LE)
///      5    4  TID da thread do RSE     (LE)
///      9    8  endereco base do modulo carregado (LE) — diagnostico
/// ```
///
/// O Loader confere a versao e registra o resto. Base e PID ajudam a casar este
/// processo com o que ele criou, quando algo der errado e for preciso investigar.
pub const HELLO_ACK_LEN: usize = 17;

pub fn montar_hello_ack(versao: u8, pid: u32, tid: u32, base: u64) -> [u8; HELLO_ACK_LEN] {
    let mut p = [0u8; HELLO_ACK_LEN];
    p[0] = versao;
    p[1..5].copy_from_slice(&pid.to_le_bytes());
    p[5..9].copy_from_slice(&tid.to_le_bytes());
    p[9..17].copy_from_slice(&base.to_le_bytes());
    p
}

pub struct HelloAck {
    pub versao: u8,
    pub pid: u32,
    pub tid: u32,
    pub base: u64,
}

pub fn ler_hello_ack(p: &[u8]) -> Option<HelloAck> {
    if p.len() < HELLO_ACK_LEN {
        return None;
    }
    Some(HelloAck {
        versao: p[0],
        pid: u32::from_le_bytes([p[1], p[2], p[3], p[4]]),
        tid: u32::from_le_bytes([p[5], p[6], p[7], p[8]]),
        base: u64::from_le_bytes([p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16]]),
    })
}

/// Payload do `HEARTBEAT` (DLL -> Loader): um contador que so cresce.
///
/// O contador nao e essencial — o proprio `seq` do frame ja e monotonico — mas
/// ele aparece no log dos dois lados e torna obvio, num rastreio, quantos
/// batimentos se passaram. Custa 4 bytes.
pub const HEARTBEAT_LEN: usize = 4;

pub fn montar_heartbeat(contador: u32) -> [u8; HEARTBEAT_LEN] {
    contador.to_le_bytes()
}

pub fn ler_heartbeat(p: &[u8]) -> Option<u32> {
    if p.len() < HEARTBEAT_LEN {
        return None;
    }
    Some(u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_ack_ida_e_volta() {
        let p = montar_hello_ack(1, 0x1234, 0x5678, 0x0040_0000);
        let r = ler_hello_ack(&p).unwrap();
        assert_eq!(r.versao, 1);
        assert_eq!(r.pid, 0x1234);
        assert_eq!(r.tid, 0x5678);
        assert_eq!(r.base, 0x0040_0000);
    }

    #[test]
    fn hello_ack_curto_reprova() {
        assert!(ler_hello_ack(&[0u8; HELLO_ACK_LEN - 1]).is_none());
    }

    #[test]
    fn heartbeat_ida_e_volta() {
        assert_eq!(ler_heartbeat(&montar_heartbeat(42)).unwrap(), 42);
        assert_eq!(ler_heartbeat(&montar_heartbeat(u32::MAX)).unwrap(), u32::MAX);
    }

    #[test]
    fn heartbeat_curto_reprova() {
        assert!(ler_heartbeat(&[0u8; 3]).is_none());
    }
}
