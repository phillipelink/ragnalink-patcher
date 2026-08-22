//! Canal cifrado da DLL com o Loader, sobre named pipe.
//!
//! # O aperto de mao, e por que a ordem importa
//!
//! ```text
//! Loader                              DLL (aqui)
//!   |  cria o pipe (servidor)           |
//!   |                                   |  conecta (cliente)
//!   |  --- HELLO (0x01) ------------->  |  decifra com K_l2d
//!   |                                   |  monta HELLO_ACK
//!   |  <-- HELLO_ACK (0x02) ---------   |  cifra com K_d2l
//!   |  ResumeThread SO AGORA            |
//! ```
//!
//! O Loader nao retoma o jogo enquanto nao receber o `HELLO_ACK`. Um cliente
//! retomado sem a DLL viva e um cliente desprotegido - a janela exata que o RSE
//! existe para fechar. Por isso o `HELLO_ACK` e uma condicao, nao uma cortesia.
//!
//! # Heartbeat
//!
//! Depois do aperto de mao, a DLL manda `HEARTBEAT` a cada 5 s e espera o
//! `HEARTBEAT_ACK` em 2 s. Tres batimentos sem resposta = o Loader sumiu (ou foi
//! morto por quem quer o jogo sem vigilancia), e a DLL derruba o proprio
//! processo. Perder o Loader e um evento de seguranca, nao um erro de rede.

#![cfg(windows)]

use rse_protocol::crypto::{derive_channel_key, Direction, Key};
use rse_protocol::frame::{Opcode, Opener, Sealer};
use rse_protocol::version::{RSE_PROTOCOL, SESSION_ID_LEN};

use crate::mensagens;
use crate::sys;

/// Quantos batimentos sem `HEARTBEAT_ACK` antes de considerar o Loader perdido.
const BATIMENTOS_PERDIDOS_ATE_MORRER: u32 = 3;
const INTERVALO_HEARTBEAT_MS: u32 = 5_000;
const PRAZO_ACK_MS: u32 = 2_000;
/// Prazo para o Loader mandar o HELLO depois que conectamos.
const PRAZO_HELLO_MS: u32 = 5_000;

/// Roda o canal inteiro: conecta, aperta a mao, e mantem o heartbeat ate o fim.
///
/// So retorna quando o canal cai. O chamador (a thread do RSE) trata o retorno
/// como fim de vida: em erro, derruba o processo.
pub fn rodar(
    pipe_name: &str,
    session_key: &Key,
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<(), String> {
    let k_l2d = derive_channel_key(session_key, session_id, Direction::LoaderToDll);
    let k_d2l = derive_channel_key(session_key, session_id, Direction::DllToLoader);

    let mut opener = Opener::new(&k_l2d, Direction::LoaderToDll);
    let mut sealer = Sealer::new(&k_d2l, Direction::DllToLoader);

    let pipe = sys::Pipe::conectar(pipe_name, PRAZO_HELLO_MS)
        .map_err(|e| format!("nao conectei no pipe do Loader: {}", e))?;

    apertar_mao(&pipe, &mut opener, &mut sealer)?;
    manter_heartbeat(&pipe, &mut opener, &mut sealer)
}

fn apertar_mao(pipe: &sys::Pipe, opener: &mut Opener, sealer: &mut Sealer) -> Result<(), String> {
    // 1. esperar o HELLO
    let bruto = pipe
        .ler(PRAZO_HELLO_MS)
        .map_err(|e| format!("esperando HELLO: {}", e))?;
    let hello = opener
        .open(&bruto)
        .map_err(|e| format!("HELLO nao autenticou ({}): chave de sessao errada?", e))?;
    if hello.opcode_raw != Opcode::Hello.as_u8() {
        return Err(format!("esperava HELLO, veio opcode 0x{:02x}", hello.opcode_raw));
    }

    // 2. responder HELLO_ACK
    let payload = mensagens::montar_hello_ack(
        RSE_PROTOCOL,
        sys::pid_atual(),
        sys::tid_atual(),
        sys::base_do_modulo(),
    );
    let frame = sealer
        .seal(Opcode::HelloAck, &payload)
        .map_err(|e| format!("cifrando HELLO_ACK: {}", e))?;
    pipe.escrever(&frame)
        .map_err(|e| format!("enviando HELLO_ACK: {}", e))?;
    Ok(())
}

fn manter_heartbeat(
    pipe: &sys::Pipe,
    opener: &mut Opener,
    sealer: &mut Sealer,
) -> Result<(), String> {
    let mut contador: u32 = 0;
    let mut perdidos: u32 = 0;

    loop {
        sys::dormir_ms(INTERVALO_HEARTBEAT_MS);

        contador = contador.wrapping_add(1);
        let payload = mensagens::montar_heartbeat(contador);
        let frame = sealer
            .seal(Opcode::Heartbeat, &payload)
            .map_err(|e| format!("cifrando HEARTBEAT: {}", e))?;
        if let Err(e) = pipe.escrever(&frame) {
            return Err(format!("Loader nao aceitou o HEARTBEAT: {}", e));
        }

        // Esperar o ACK. Timeout NAO e erro fatal na hora: pode ser um batimento
        // perdido isolado. So a sequencia de tres seguidos derruba.
        match pipe.ler(PRAZO_ACK_MS) {
            Ok(bruto) => match opener.open(&bruto) {
                Ok(f) if f.opcode_raw == Opcode::HeartbeatAck.as_u8() => {
                    perdidos = 0;
                }
                Ok(f) if f.opcode_raw == Opcode::Shutdown.as_u8() => {
                    // Encerramento limpo pedido pelo Loader (jogo fechando, ou
                    // kill-switch). Nao e falha.
                    return Ok(());
                }
                Ok(f) => {
                    // Opcode inesperado: registrar e ignorar, como manda o
                    // protocolo. Nao conta como batimento perdido.
                    let _ = f;
                }
                Err(_) => {
                    // Frame corrompido no meio do canal cifrado e serio, mas o
                    // caminho conservador aqui e tratar como batimento perdido e
                    // deixar o contador decidir.
                    perdidos += 1;
                }
            },
            Err(_) => {
                perdidos += 1;
            }
        }

        if perdidos >= BATIMENTOS_PERDIDOS_ATE_MORRER {
            return Err(format!(
                "{} batimentos sem resposta do Loader — encerrando o cliente",
                perdidos
            ));
        }
    }
}
