//! # RagnaShield Engine — protocolo compartilhado
//!
//! Biblioteca comum ao launcher (`rpatchur`), ao `rse-loader` e ao
//! `rse-watchdog`. Define o formato do **ticket** que o login-server valida e o
//! **canal autenticado** entre o Loader e a DLL.
//!
//! ## O que este crate NAO faz, e nao vai fazer
//!
//! Nada de I/O, nada de Windows API, nada de tokio, nada de `unsafe`. Bytes
//! entram por parametro e bytes saem por retorno. E o que permite testar o
//! protocolo inteiro em CI, em qualquer maquina, e portar a verificacao para o
//! login-server sem arrastar o resto do mundo junto.
//!
//! ## Uso típico
//!
//! ```
//! use rse_protocol::crypto::{Key, TestOnlySeededRandom};
//! use rse_protocol::replay::MemoryReplayGuard;
//! use rse_protocol::ticket::{
//!     encode_login_packet, parse_login_packet, verify, RseTicket, SingleKey,
//!     TicketFlags, VerifyOptions,
//! };
//! use rse_protocol::version::TICKET_DEFAULT_TTL_MS;
//!
//! // --- no RSE Auth Service (unico lugar que tem K_ticket) ---
//! let k_ticket = Key::from_bytes([0x42; 32]);
//! let mut rng = TestOnlySeededRandom::new(1); // em producao: OsRandom
//! let agora = 1_800_000_000_000u64;
//!
//! let ticket = RseTicket::issue(
//!     &mut rng,
//!     TicketFlags::empty().with(TicketFlags::STRICT),
//!     1,                       // key_id
//!     agora,
//!     TICKET_DEFAULT_TTL_MS,
//!     [0xB2; 16],              // session_id
//!     [0xC3; 32],              // machine_fp
//!     [0xD4; 32],              // client_hash
//! ).expect("entropia disponivel");
//!
//! let bytes = ticket.encode(&k_ticket);
//! let packet = encode_login_packet(&bytes);   // 0x0AAA, 152 bytes
//!
//! // --- no login-server ---
//! let recebido = parse_login_packet(&packet).expect("packet 0x0AAA");
//! let chaveiro = SingleKey::new(1, Key::from_bytes([0x42; 32]));
//! let mut replay = MemoryReplayGuard::new(4096);
//!
//! let ok = verify(recebido, &chaveiro, agora + 50, &VerifyOptions::default(), &mut replay)
//!     .expect("ticket valido");
//! assert!(ok.flags.strict());
//!
//! // o mesmo ticket uma segunda vez nao passa
//! assert!(verify(recebido, &chaveiro, agora + 60, &VerifyOptions::default(), &mut replay).is_err());
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_debug_implementations)]

pub mod crypto;
pub mod dll_config;
pub mod error;
pub mod frame;
pub mod handover;
pub mod replay;
pub mod ticket;
pub mod version;

pub use error::{FrameError, RandomError, TicketError};
pub use frame::{Channel, OpenedFrame, Opcode, Opener, Sealer};
pub use replay::{MemoryReplayGuard, NoReplayGuard, ReplayGuard};
pub use ticket::{
    encode_login_packet, parse_login_packet, verify, KeyRing, KeyRingSet, RseTicket, SingleKey,
    TicketFlags, VerifyOptions,
};
pub use version::RSE_PROTOCOL;
