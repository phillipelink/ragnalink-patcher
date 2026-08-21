//! Canal Loader <-> DLL: frames autenticados com AES-256-GCM.
//!
//! O transporte real e um named pipe local, e ele NAO e implementado aqui (este
//! crate nao faz I/O). Aqui ficam so os bytes: como um frame vira sequencia de
//! octetos e como uma sequencia de octetos vira um frame - com autenticacao e
//! protecao contra reenvio.

use crate::crypto::{Direction, Key};
use crate::error::FrameError;
use crate::version::*;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

/// Opcodes do canal (docs/RSE_SPEC.md, secao 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Loader -> DLL: build esperado, session_id, politica.
    Hello = 0x01,
    /// DLL -> Loader: versao, PID, TID, base carregada.
    HelloAck = 0x02,
    /// DLL -> Loader, a cada 5 s.
    Heartbeat = 0x10,
    /// Loader -> DLL, em ate 2 s.
    HeartbeatAck = 0x11,
    /// DLL -> Loader: preciso de um ticket agora.
    TicketReq = 0x20,
    /// Loader -> DLL: os 148 bytes, ou um codigo de erro.
    TicketRsp = 0x21,
    /// DLL -> Loader: violacao detectada.
    Report = 0x30,
    /// Loader -> DLL: ignore / warn / kill.
    ReportAck = 0x31,
    /// Loader -> DLL: politica atualizada.
    Policy = 0x40,
    /// Encerramento limpo, com motivo. Vale nas duas direcoes.
    Shutdown = 0x7F,
}

impl Opcode {
    pub fn from_u8(v: u8) -> Result<Opcode, FrameError> {
        Ok(match v {
            0x01 => Opcode::Hello,
            0x02 => Opcode::HelloAck,
            0x10 => Opcode::Heartbeat,
            0x11 => Opcode::HeartbeatAck,
            0x20 => Opcode::TicketReq,
            0x21 => Opcode::TicketRsp,
            0x30 => Opcode::Report,
            0x31 => Opcode::ReportAck,
            0x40 => Opcode::Policy,
            0x7F => Opcode::Shutdown,
            _ => return Err(FrameError::UnknownOpcode),
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Um frame aberto e autenticado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFrame {
    pub seq: u32,
    /// O byte cru, mesmo quando nao corresponde a nenhum opcode conhecido.
    pub opcode_raw: u8,
    /// `None` para opcode desconhecido.
    ///
    /// 🚨 Opcode desconhecido NAO e motivo para derrubar a conexao. Registre e
    /// ignore o frame. E o que permite acrescentar opcode novo sem quebrar quem
    /// ainda esta com a DLL antiga em campo.
    pub opcode: Option<Opcode>,
    pub payload: Vec<u8>,
}

/// Ponta que ESCREVE numa direcao.
pub struct Sealer {
    cipher: Aes256Gcm,
    salt: [u8; 4],
    next_seq: u32,
}

/// Ponta que LE numa direcao.
pub struct Opener {
    cipher: Aes256Gcm,
    salt: [u8; 4],
    last_seq: Option<u32>,
}

fn cipher_from(key: &Key) -> Aes256Gcm {
    // `new` da AES-256-GCM aceita exatamente 32 bytes, que e o tamanho fixo de
    // `Key`. Nao ha caminho de falha.
    Aes256Gcm::new(key.as_bytes().into())
}

/// Monta o nonce de 12 bytes: `salt(4) || seq(8, little-endian)`.
///
/// Deterministico DE PROPOSITO. Nonce sorteado teria chance de colisao, e em
/// GCM colisao de nonce com a mesma chave nao "enfraquece um pouco": permite
/// recuperar a chave de autenticacao e forjar mensagens. Contador que so cresce
/// nunca colide - e por isso o estouro do contador (`SequenceExhausted`) e um
/// erro duro em vez de dar a volta.
fn make_nonce(salt: &[u8; 4], seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(salt);
    n[4..].copy_from_slice(&(seq as u64).to_le_bytes());
    n
}

fn write_header(opcode: u8, seq: u32, payload_len: u16, salt: &[u8; 4]) -> [u8; FRAME_HEADER_LEN] {
    let mut h = [0u8; FRAME_HEADER_LEN];
    h[0..2].copy_from_slice(&FRAME_MAGIC);
    h[2] = RSE_PROTOCOL;
    h[3] = opcode;
    h[4..8].copy_from_slice(&seq.to_le_bytes());
    h[8..10].copy_from_slice(&payload_len.to_le_bytes());
    h[10..12].copy_from_slice(&0u16.to_le_bytes()); // flags, reservado
    h[12..24].copy_from_slice(&make_nonce(salt, seq));
    h
}

impl Sealer {
    /// Cria a ponta de escrita a partir da chave JA DERIVADA daquela direcao.
    pub fn new(channel_key: &Key, dir: Direction) -> Self {
        Sealer {
            cipher: cipher_from(channel_key),
            salt: dir.nonce_salt(),
            next_seq: 1, // seq 0 nao e usado: facilita distinguir "sem frame ainda"
        }
    }

    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Cifra e serializa um frame.
    pub fn seal(&mut self, opcode: Opcode, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        self.seal_raw(opcode.as_u8(), payload)
    }

    /// Versao que aceita opcode cru — util para testar compatibilidade futura.
    pub fn seal_raw(&mut self, opcode: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        if payload.len() > FRAME_MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge);
        }
        if self.next_seq == u32::MAX {
            // A sessao precisa recomecar com chave nova. Dar a volta no contador
            // repetiria nonce - ver o comentario de `make_nonce`.
            return Err(FrameError::SequenceExhausted);
        }
        let seq = self.next_seq;
        let header = write_header(opcode, seq, payload.len() as u16, &self.salt);
        let nonce = make_nonce(&self.salt, seq);

        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: &header[..FRAME_AAD_LEN],
                },
            )
            .map_err(|_| FrameError::Decrypt)?;

        self.next_seq += 1;

        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

impl Opener {
    /// Cria a ponta de leitura a partir da chave JA DERIVADA daquela direcao.
    pub fn new(channel_key: &Key, dir: Direction) -> Self {
        Opener {
            cipher: cipher_from(channel_key),
            salt: dir.nonce_salt(),
            last_seq: None,
        }
    }

    pub fn last_seq(&self) -> Option<u32> {
        self.last_seq
    }

    /// Quantos bytes tem o frame que comeca em `buf`, se der para saber.
    ///
    /// O named pipe do RSE roda em modo mensagem, mas quem for ler de um stream
    /// precisa disto para saber onde termina um frame e comeca o proximo.
    pub fn frame_len(buf: &[u8]) -> Result<usize, FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Truncated);
        }
        if buf[0..2] != FRAME_MAGIC {
            return Err(FrameError::BadMagic);
        }
        let payload_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
        if payload_len > FRAME_MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge);
        }
        Ok(FRAME_HEADER_LEN + payload_len + FRAME_TAG_LEN)
    }

    /// Autentica, decifra e devolve o frame.
    ///
    /// 🚨 ORDEM: decifra PRIMEIRO, so depois confere o `seq`. O contador so
    /// avanca com frame autenticado. Se a checagem viesse antes, alguem sem a
    /// chave conseguiria empurrar o `last_seq` para o teto mandando lixo com
    /// `seq` alto - e a partir dai a ponta legitima nao conseguiria mais falar.
    pub fn open(&mut self, buf: &[u8]) -> Result<OpenedFrame, FrameError> {
        let total = Self::frame_len(buf)?;
        if buf.len() < total {
            return Err(FrameError::Truncated);
        }
        if buf[2] != RSE_PROTOCOL && !version_supported(buf[2]) {
            return Err(FrameError::BadVersion);
        }

        let opcode_raw = buf[3];
        let seq = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let payload_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;

        // O nonce vem no cabecalho por conveniencia de diagnostico, mas e
        // derivavel do `seq`. Exigir que bata fecha a porta para quem tentar
        // brincar com nonce arbitrario.
        let expected_nonce = make_nonce(&self.salt, seq);
        if buf[12..24] != expected_nonce {
            return Err(FrameError::Decrypt);
        }

        let body = &buf[FRAME_HEADER_LEN..total];
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(&expected_nonce),
                Payload {
                    msg: body,
                    aad: &buf[..FRAME_AAD_LEN],
                },
            )
            .map_err(|_| FrameError::Decrypt)?;

        if plain.len() != payload_len {
            // Cabecalho autenticado dizendo um tamanho e conteudo com outro nao
            // deveria acontecer nunca; se acontecer, e bug nosso, nao ataque.
            return Err(FrameError::Decrypt);
        }

        // Autenticado. Agora sim, o contador.
        if let Some(last) = self.last_seq {
            if seq <= last {
                return Err(FrameError::ReplayedSequence);
            }
        }
        self.last_seq = Some(seq);

        Ok(OpenedFrame {
            seq,
            opcode_raw,
            opcode: Opcode::from_u8(opcode_raw).ok(),
            payload: plain,
        })
    }
}

impl core::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealer")
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Opener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opener")
            .field("last_seq", &self.last_seq)
            .finish_non_exhaustive()
    }
}

/// As duas pontas de um lado do canal, ja montadas.
#[derive(Debug)]
pub struct Channel {
    pub out: Sealer,
    pub inbound: Opener,
}

impl Channel {
    /// `mine` e a direcao em que ESTA ponta escreve.
    ///
    /// No Loader: `Direction::LoaderToDll`. Na DLL: `Direction::DllToLoader`.
    /// Trocar isso faz as duas pontas cifrarem com a mesma chave e nada abrir -
    /// e o sintoma seria "o handshake nunca completa", que e chato de rastrear.
    pub fn new(k_l2d: &Key, k_d2l: &Key, mine: Direction) -> Self {
        match mine {
            Direction::LoaderToDll => Channel {
                out: Sealer::new(k_l2d, Direction::LoaderToDll),
                inbound: Opener::new(k_d2l, Direction::DllToLoader),
            },
            Direction::DllToLoader => Channel {
                out: Sealer::new(k_d2l, Direction::DllToLoader),
                inbound: Opener::new(k_l2d, Direction::LoaderToDll),
            },
        }
    }
}

#[cfg(test)]
// Em teste, `expect` e `assert` sao a ferramenta certa: falha de teste DEVE
// abortar com mensagem. A proibicao de panico vale para o codigo que roda
// dentro do processo do jogo, nao para o que roda no CI.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::{derive_channel_keys, Key};
    use crate::version::{KEY_LEN, SESSION_ID_LEN};

    fn par() -> (Channel, Channel) {
        let ks = Key::from_bytes([0x5A; KEY_LEN]);
        let sid = [0x11; SESSION_ID_LEN];
        let (l2d, d2l) = derive_channel_keys(&ks, &sid);
        (
            Channel::new(&l2d, &d2l, Direction::LoaderToDll),
            Channel::new(&l2d, &d2l, Direction::DllToLoader),
        )
    }

    #[test]
    fn ida_e_volta_nas_duas_direcoes() {
        let (mut loader, mut dll) = par();

        let f = loader.out.seal(Opcode::Hello, b"politica").expect("seal");
        let o = dll.inbound.open(&f).expect("open");
        assert_eq!(o.opcode, Some(Opcode::Hello));
        assert_eq!(o.payload, b"politica");
        assert_eq!(o.seq, 1);

        let g = dll.out.seal(Opcode::HelloAck, b"pid=1234").expect("seal");
        let p = loader.inbound.open(&g).expect("open");
        assert_eq!(p.opcode, Some(Opcode::HelloAck));
        assert_eq!(p.payload, b"pid=1234");
    }

    #[test]
    fn payload_vazio_e_payload_no_teto() {
        let (mut loader, mut dll) = par();

        let f = loader.out.seal(Opcode::Heartbeat, b"").expect("vazio");
        assert_eq!(dll.inbound.open(&f).expect("open").payload.len(), 0);

        let grande = vec![0xABu8; FRAME_MAX_PAYLOAD];
        let g = loader.out.seal(Opcode::Policy, &grande).expect("teto");
        assert_eq!(dll.inbound.open(&g).expect("open").payload, grande);

        let demais = vec![0u8; FRAME_MAX_PAYLOAD + 1];
        assert_eq!(
            loader.out.seal(Opcode::Policy, &demais).unwrap_err(),
            FrameError::PayloadTooLarge
        );
    }

    #[test]
    fn um_byte_alterado_em_qualquer_lugar_reprova() {
        let (mut loader, _) = par();
        let base = loader.out.seal(Opcode::Report, b"1000:critico").expect("seal");
        for i in 0..base.len() {
            let (_, mut dll) = par();
            let mut f = base.clone();
            f[i] ^= 0xFF;
            assert!(
                dll.inbound.open(&f).is_err(),
                "byte {} passou sem ser notado",
                i
            );
        }
    }

    #[test]
    fn frame_repetido_e_barrado() {
        let (mut loader, mut dll) = par();
        let f = loader.out.seal(Opcode::Heartbeat, b"1").expect("seal");
        assert!(dll.inbound.open(&f).is_ok());
        assert_eq!(
            dll.inbound.open(&f).unwrap_err(),
            FrameError::ReplayedSequence
        );
    }

    #[test]
    fn seq_fora_de_ordem_e_barrado() {
        let (mut loader, mut dll) = par();
        let f1 = loader.out.seal(Opcode::Heartbeat, b"1").expect("seal");
        let f2 = loader.out.seal(Opcode::Heartbeat, b"2").expect("seal");
        let f3 = loader.out.seal(Opcode::Heartbeat, b"3").expect("seal");

        assert!(dll.inbound.open(&f1).is_ok());
        assert!(dll.inbound.open(&f3).is_ok()); // pular pra frente e permitido
        assert_eq!(
            dll.inbound.open(&f2).unwrap_err(),
            FrameError::ReplayedSequence
        ); // voltar, nao
    }

    #[test]
    fn frame_invalido_nao_avanca_o_contador() {
        let (mut loader, mut dll) = par();
        let f1 = loader.out.seal(Opcode::Heartbeat, b"1").expect("seal");
        let f2 = loader.out.seal(Opcode::Heartbeat, b"2").expect("seal");

        // lixo com seq altissimo: nao pode envenenar o estado do receptor
        let mut lixo = f2.clone();
        lixo[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(dll.inbound.open(&lixo).is_err());
        assert_eq!(dll.inbound.last_seq(), None);

        // os frames legitimos continuam funcionando
        assert!(dll.inbound.open(&f1).is_ok());
        assert!(dll.inbound.open(&f2).is_ok());
    }

    #[test]
    fn chave_da_direcao_errada_nao_abre() {
        let ks = Key::from_bytes([0x5A; KEY_LEN]);
        let sid = [0x11; SESSION_ID_LEN];
        let (l2d, d2l) = derive_channel_keys(&ks, &sid);

        let mut sealer = Sealer::new(&l2d, Direction::LoaderToDll);
        // opener montado com a chave errada de proposito
        let mut opener = Opener::new(&d2l, Direction::LoaderToDll);
        let f = sealer.seal(Opcode::Hello, b"x").expect("seal");
        assert_eq!(opener.open(&f).unwrap_err(), FrameError::Decrypt);
    }

    #[test]
    fn sessao_diferente_nao_abre() {
        let ks = Key::from_bytes([0x5A; KEY_LEN]);
        let (a_l2d, a_d2l) = derive_channel_keys(&ks, &[0x11; SESSION_ID_LEN]);
        let (b_l2d, b_d2l) = derive_channel_keys(&ks, &[0x22; SESSION_ID_LEN]);

        let mut a = Channel::new(&a_l2d, &a_d2l, Direction::LoaderToDll);
        let mut b = Channel::new(&b_l2d, &b_d2l, Direction::DllToLoader);

        let f = a.out.seal(Opcode::Hello, b"x").expect("seal");
        assert_eq!(b.inbound.open(&f).unwrap_err(), FrameError::Decrypt);
    }

    #[test]
    fn opcode_desconhecido_chega_como_none_e_nao_como_erro() {
        let (mut loader, mut dll) = par();
        let f = loader.out.seal_raw(0x6E, b"experimental").expect("seal");
        let o = dll.inbound.open(&f).expect("frame valido");
        assert_eq!(o.opcode, None);
        assert_eq!(o.opcode_raw, 0x6E);
        assert_eq!(o.payload, b"experimental");
    }

    #[test]
    fn truncado_e_magic_errado() {
        let (mut loader, mut dll) = par();
        let f = loader.out.seal(Opcode::Hello, b"abc").expect("seal");
        assert_eq!(
            dll.inbound.open(&f[..10]).unwrap_err(),
            FrameError::Truncated
        );
        assert_eq!(
            dll.inbound.open(&f[..f.len() - 1]).unwrap_err(),
            FrameError::Truncated
        );
        let mut m = f.clone();
        m[0] = b'X';
        assert_eq!(dll.inbound.open(&m).unwrap_err(), FrameError::BadMagic);
    }

    #[test]
    fn frame_len_bate_com_o_tamanho_real() {
        let (mut loader, _) = par();
        for n in [0usize, 1, 100, 8192] {
            let f = loader.out.seal(Opcode::Policy, &vec![7u8; n]).expect("seal");
            assert_eq!(Opener::frame_len(&f).expect("len"), f.len());
            assert_eq!(f.len(), FRAME_HEADER_LEN + n + FRAME_TAG_LEN);
        }
    }

    #[test]
    fn nonce_nunca_se_repete_na_mesma_direcao() {
        let (mut loader, _) = par();
        let mut vistos = std::collections::HashSet::new();
        for i in 0..500 {
            let f = loader.out.seal(Opcode::Heartbeat, b"x").expect("seal");
            assert!(vistos.insert(f[12..24].to_vec()), "nonce repetido em {}", i);
        }
    }

    #[test]
    fn nonce_adulterado_no_cabecalho_e_recusado() {
        let (mut loader, mut dll) = par();
        let mut f = loader.out.seal(Opcode::Hello, b"x").expect("seal");
        f[12] ^= 0x01;
        assert_eq!(dll.inbound.open(&f).unwrap_err(), FrameError::Decrypt);
    }

    #[test]
    fn opcodes_ida_e_volta() {
        for op in [
            Opcode::Hello,
            Opcode::HelloAck,
            Opcode::Heartbeat,
            Opcode::HeartbeatAck,
            Opcode::TicketReq,
            Opcode::TicketRsp,
            Opcode::Report,
            Opcode::ReportAck,
            Opcode::Policy,
            Opcode::Shutdown,
        ] {
            assert_eq!(Opcode::from_u8(op.as_u8()).expect("conhecido"), op);
        }
        assert_eq!(Opcode::from_u8(0x00).unwrap_err(), FrameError::UnknownOpcode);
        assert_eq!(Opcode::from_u8(0xFF).unwrap_err(), FrameError::UnknownOpcode);
    }
}
