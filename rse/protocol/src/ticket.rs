//! RSE Ticket v1 — a credencial que o login-server valida.
//!
//! É o coracao do RSE. Tudo o mais (Loader, DLL, deteccoes) pode falhar ou ser
//! contornado num cliente individual; o ticket e o que impede alguem de trocar
//! o launcher inteiro e conectar mesmo assim.
//!
//! 🚨 A PROPRIEDADE QUE FAZ ISTO FUNCIONAR, e que e facil destruir sem perceber:
//! quem ASSINA e o servidor. `K_ticket` existe em dois lugares no mundo - o RSE
//! Auth Service e o login-server. Ela NAO pode estar no launcher, no Loader, na
//! DLL, em arquivo distribuido nem em repositorio. No dia em que estiver, o
//! ticket vira enfeite: qualquer um extrai a chave do executavel e forja quantos
//! quiser. Ver ADR-005 em docs/ARCHITECTURE.md.

use crate::crypto::{hmac_sha256, mac_equal, Key, RandomSource};
use crate::error::{RandomError, TicketError};
use crate::replay::ReplayGuard;
use crate::version::*;

/// Bandeiras do ticket (byte 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TicketFlags(pub u8);

impl TicketFlags {
    pub const STRICT: u8 = 0b0000_0001;
    pub const VIP: u8 = 0b0000_0010;
    pub const STAFF: u8 = 0b0000_0100;

    pub fn empty() -> Self {
        TicketFlags(0)
    }
    pub fn with(mut self, bit: u8) -> Self {
        self.0 |= bit;
        self
    }
    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
    pub fn strict(self) -> bool {
        self.has(Self::STRICT)
    }
    pub fn vip(self) -> bool {
        self.has(Self::VIP)
    }
    pub fn staff(self) -> bool {
        self.has(Self::STAFF)
    }
}

/// Um ticket, ja em forma de struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RseTicket {
    pub version: u8,
    pub flags: TicketFlags,
    /// Qual `K_ticket` assinou. Existe para permitir rotacao de chave sem
    /// derrubar o servidor: durante a troca, o verificador aceita as duas.
    pub key_id: u8,
    /// Unix em MILISSEGUNDOS, UTC. Milissegundo e nao segundo porque o TTL e de
    /// 30 s - com granularidade de segundo, o erro de arredondamento seria 3%
    /// da janela inteira.
    pub issued_at_ms: u64,
    pub ttl_ms: u32,
    /// Chave do cache de replay. CSPRNG, 16 bytes.
    pub nonce: [u8; TICKET_NONCE_LEN],
    /// Sessao do Loader.
    pub session_id: [u8; SESSION_ID_LEN],
    /// Impressao de maquina - hash com pepper do servidor. Ver secao 8 do
    /// RSE_SPEC: identificador de hardware cru NUNCA sai da maquina do jogador.
    pub machine_fp: [u8; FINGERPRINT_LEN],
    /// SHA-256 do manifesto de integridade.
    pub client_hash: [u8; 32],
}

impl RseTicket {
    /// Monta um ticket novo. So o Auth Service deveria chamar isto.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flags: TicketFlags,
        key_id: u8,
        issued_at_ms: u64,
        ttl_ms: u32,
        nonce: [u8; TICKET_NONCE_LEN],
        session_id: [u8; SESSION_ID_LEN],
        machine_fp: [u8; FINGERPRINT_LEN],
        client_hash: [u8; 32],
    ) -> Self {
        RseTicket {
            version: RSE_PROTOCOL,
            flags,
            key_id,
            issued_at_ms,
            ttl_ms,
            nonce,
            session_id,
            machine_fp,
            client_hash,
        }
    }

    /// Monta um ticket sorteando o `nonce` da fonte informada.
    ///
    /// Preferir esta forma: nonce escolhido a mao (ou reaproveitado) e a maneira
    /// mais facil de destruir a protecao contra replay.
    #[allow(clippy::too_many_arguments)]
    pub fn issue<R: RandomSource>(
        rng: &mut R,
        flags: TicketFlags,
        key_id: u8,
        issued_at_ms: u64,
        ttl_ms: u32,
        session_id: [u8; SESSION_ID_LEN],
        machine_fp: [u8; FINGERPRINT_LEN],
        client_hash: [u8; 32],
    ) -> Result<Self, RandomError> {
        let mut nonce = [0u8; TICKET_NONCE_LEN];
        rng.fill(&mut nonce)?;
        Ok(Self::new(
            flags,
            key_id,
            issued_at_ms,
            ttl_ms,
            nonce,
            session_id,
            machine_fp,
            client_hash,
        ))
    }

    /// Instante em que este ticket deixa de valer.
    pub fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms.saturating_add(self.ttl_ms as u64)
    }

    /// Serializa e assina. Devolve os 148 bytes prontos para a rede.
    pub fn encode(&self, key: &Key) -> [u8; TICKET_LEN] {
        let mut b = [0u8; TICKET_LEN];
        b[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&TICKET_MAGIC);
        b[OFF_VERSION] = self.version;
        b[OFF_FLAGS] = self.flags.0;
        b[OFF_KEY_ID] = self.key_id;
        b[OFF_RESERVED] = 0;
        b[OFF_ISSUED_AT..OFF_ISSUED_AT + 8].copy_from_slice(&self.issued_at_ms.to_be_bytes());
        b[OFF_TTL..OFF_TTL + 4].copy_from_slice(&self.ttl_ms.to_be_bytes());
        b[OFF_NONCE..OFF_NONCE + TICKET_NONCE_LEN].copy_from_slice(&self.nonce);
        b[OFF_SESSION_ID..OFF_SESSION_ID + SESSION_ID_LEN].copy_from_slice(&self.session_id);
        b[OFF_MACHINE_FP..OFF_MACHINE_FP + FINGERPRINT_LEN].copy_from_slice(&self.machine_fp);
        b[OFF_CLIENT_HASH..OFF_CLIENT_HASH + 32].copy_from_slice(&self.client_hash);

        let mac = hmac_sha256(key, &b[..TICKET_SIGNED_LEN]);
        b[OFF_HMAC..OFF_HMAC + MAC_LEN].copy_from_slice(&mac);
        b
    }

    /// Le os campos SEM conferir assinatura, validade ou replay.
    ///
    /// 🚨 Isto NAO autentica nada. Serve para log de diagnostico e para as
    /// ferramentas de inspecao. Em caminho de autenticacao, use `verify`.
    pub fn parse_unverified(bytes: &[u8]) -> Result<RseTicket, TicketError> {
        if bytes.len() != TICKET_LEN {
            return Err(TicketError::InvalidLength);
        }
        if bytes[OFF_MAGIC..OFF_MAGIC + 4] != TICKET_MAGIC {
            return Err(TicketError::BadMagic);
        }
        let mut nonce = [0u8; TICKET_NONCE_LEN];
        let mut session_id = [0u8; SESSION_ID_LEN];
        let mut machine_fp = [0u8; FINGERPRINT_LEN];
        let mut client_hash = [0u8; 32];
        nonce.copy_from_slice(&bytes[OFF_NONCE..OFF_NONCE + TICKET_NONCE_LEN]);
        session_id.copy_from_slice(&bytes[OFF_SESSION_ID..OFF_SESSION_ID + SESSION_ID_LEN]);
        machine_fp.copy_from_slice(&bytes[OFF_MACHINE_FP..OFF_MACHINE_FP + FINGERPRINT_LEN]);
        client_hash.copy_from_slice(&bytes[OFF_CLIENT_HASH..OFF_CLIENT_HASH + 32]);

        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[OFF_ISSUED_AT..OFF_ISSUED_AT + 8]);
        let mut tt = [0u8; 4];
        tt.copy_from_slice(&bytes[OFF_TTL..OFF_TTL + 4]);

        Ok(RseTicket {
            version: bytes[OFF_VERSION],
            flags: TicketFlags(bytes[OFF_FLAGS]),
            key_id: bytes[OFF_KEY_ID],
            issued_at_ms: u64::from_be_bytes(ts),
            ttl_ms: u32::from_be_bytes(tt),
            nonce,
            session_id,
            machine_fp,
            client_hash,
        })
    }
}

/// De onde o verificador tira a chave a partir do `key_id`.
pub trait KeyRing {
    fn key_for(&self, key_id: u8) -> Option<&Key>;
}

/// Chaveiro de uma chave so - o caso normal fora da janela de rotacao.
#[derive(Debug)]
pub struct SingleKey {
    pub key_id: u8,
    pub key: Key,
}

impl SingleKey {
    pub fn new(key_id: u8, key: Key) -> Self {
        SingleKey { key_id, key }
    }
}

impl KeyRing for SingleKey {
    fn key_for(&self, key_id: u8) -> Option<&Key> {
        if key_id == self.key_id {
            Some(&self.key)
        } else {
            None
        }
    }
}

/// Chaveiro com varias chaves ativas — usado durante a rotacao.
#[derive(Debug, Default)]
pub struct KeyRingSet {
    entries: Vec<(u8, Key)>,
}

impl KeyRingSet {
    pub fn new() -> Self {
        KeyRingSet {
            entries: Vec::new(),
        }
    }
    pub fn insert(&mut self, key_id: u8, key: Key) {
        self.entries.retain(|(id, _)| *id != key_id);
        self.entries.push((key_id, key));
    }
    pub fn remove(&mut self, key_id: u8) {
        self.entries.retain(|(id, _)| *id != key_id);
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl KeyRing for KeyRingSet {
    fn key_for(&self, key_id: u8) -> Option<&Key> {
        self.entries.iter().find(|(id, _)| *id == key_id).map(|(_, k)| k)
    }
}

/// Ajustes da validacao.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Quanto o relogio do emissor pode estar adiantado.
    pub clock_skew_ms: u64,
    /// TTL maximo aceito, independente do que o ticket diga.
    pub max_ttl_ms: u32,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            clock_skew_ms: TICKET_CLOCK_SKEW_MS,
            max_ttl_ms: TICKET_MAX_TTL_MS,
        }
    }
}

/// Valida um ticket. **Offline**: sem banco, sem rede.
///
/// 🚨 A ORDEM DOS PASSOS E PARTE DA SEGURANCA, nao estilo:
///
///   1. estrutura (tamanho, magic, versao) — descarta lixo antes de gastar CPU
///   2. `key_id` conhecido
///   3. TTL dentro do teto — antes de olhar o relogio
///   4. **HMAC** — daqui pra frente o conteudo e confiavel
///   5. janela de tempo
///   6. replay — e SO AGORA o nonce entra no cache
///
/// Inverter 4 e 6 seria um buraco: um atacante mandaria tickets com nonce
/// inventado e assinatura lixo, e cada um deles ocuparia uma entrada do cache
/// ate estourar a memoria do login-server. Verificar a assinatura ANTES de
/// gravar qualquer coisa e o que impede isso.
pub fn verify(
    bytes: &[u8],
    keyring: &dyn KeyRing,
    now_ms: u64,
    opts: &VerifyOptions,
    replay: &mut dyn ReplayGuard,
) -> Result<RseTicket, TicketError> {
    // 1. estrutura
    if bytes.len() != TICKET_LEN {
        return Err(TicketError::InvalidLength);
    }
    if bytes[OFF_MAGIC..OFF_MAGIC + 4] != TICKET_MAGIC {
        return Err(TicketError::BadMagic);
    }
    if !version_supported(bytes[OFF_VERSION]) {
        return Err(TicketError::BadVersion);
    }

    // 2. chave
    let key = keyring
        .key_for(bytes[OFF_KEY_ID])
        .ok_or(TicketError::UnknownKey)?;

    // 3. TTL sensato
    let mut tt = [0u8; 4];
    tt.copy_from_slice(&bytes[OFF_TTL..OFF_TTL + 4]);
    let ttl_ms = u32::from_be_bytes(tt);
    if ttl_ms == 0 || ttl_ms > opts.max_ttl_ms {
        return Err(TicketError::BadTtl);
    }

    // 4. assinatura
    let expected = hmac_sha256(key, &bytes[..TICKET_SIGNED_LEN]);
    if !mac_equal(&expected, &bytes[OFF_HMAC..OFF_HMAC + MAC_LEN]) {
        return Err(TicketError::BadSignature);
    }

    // Conteudo autenticado: agora da pra confiar nos campos.
    let ticket = RseTicket::parse_unverified(bytes)?;

    // 5. janela de tempo
    if now_ms > ticket.expires_at_ms() {
        return Err(TicketError::Expired);
    }
    if ticket.issued_at_ms > now_ms.saturating_add(opts.clock_skew_ms) {
        return Err(TicketError::NotYetValid);
    }

    // 6. replay
    let keep_until = ticket.expires_at_ms().saturating_add(opts.clock_skew_ms);
    if !replay.check_and_insert(&ticket.nonce, keep_until, now_ms) {
        return Err(TicketError::Replay);
    }

    Ok(ticket)
}

// ---------------------------------------------------------------------------
//  Packet 0x0AAA
// ---------------------------------------------------------------------------

/// Embrulha o ticket no packet que vai ao login-server.
///
/// Header e tamanho em LITTLE-ENDIAN, como todo packet do Ragnarok. O ticket em
/// si e big-endian internamente - sao dois formatos diferentes encaixados, e
/// misturar os dois e o erro classico de quem for portar isto para C++.
pub fn encode_login_packet(ticket: &[u8; TICKET_LEN]) -> [u8; LOGIN_PACKET_LEN] {
    let mut p = [0u8; LOGIN_PACKET_LEN];
    p[0..2].copy_from_slice(&LOGIN_PACKET_ID.to_le_bytes());
    p[2..4].copy_from_slice(&(LOGIN_PACKET_LEN as u16).to_le_bytes());
    p[4..].copy_from_slice(ticket);
    p
}

/// Extrai o ticket de um packet 0x0AAA. Devolve a fatia dos 148 bytes.
///
/// Aceita buffer maior que o packet (o login-server le de uma fila que pode ter
/// o proximo packet colado atras) e devolve so o que pertence a este.
pub fn parse_login_packet(buf: &[u8]) -> Result<&[u8], TicketError> {
    if buf.len() < 4 {
        return Err(TicketError::InvalidLength);
    }
    let id = u16::from_le_bytes([buf[0], buf[1]]);
    if id != LOGIN_PACKET_ID {
        return Err(TicketError::BadMagic);
    }
    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if len != LOGIN_PACKET_LEN || buf.len() < LOGIN_PACKET_LEN {
        return Err(TicketError::InvalidLength);
    }
    Ok(&buf[4..LOGIN_PACKET_LEN])
}

#[cfg(test)]
// Em teste, `expect` e `assert` sao a ferramenta certa: falha de teste DEVE
// abortar com mensagem. A proibicao de panico vale para o codigo que roda
// dentro do processo do jogo, nao para o que roda no CI.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::TestOnlySeededRandom;
    use crate::replay::MemoryReplayGuard;

    const NOW: u64 = 1_800_000_000_000;

    fn key() -> Key {
        Key::from_bytes([0x42; KEY_LEN])
    }

    fn sample() -> RseTicket {
        RseTicket::new(
            TicketFlags::empty().with(TicketFlags::STRICT),
            1,
            NOW,
            TICKET_DEFAULT_TTL_MS,
            [0xA1; TICKET_NONCE_LEN],
            [0xB2; SESSION_ID_LEN],
            [0xC3; FINGERPRINT_LEN],
            [0xD4; 32],
        )
    }

    fn ring() -> SingleKey {
        SingleKey::new(1, key())
    }

    #[test]
    fn ticket_tem_148_bytes_e_volta_igual() {
        let t = sample();
        let b = t.encode(&key());
        assert_eq!(b.len(), TICKET_LEN);
        let back = RseTicket::parse_unverified(&b).expect("parse");
        assert_eq!(t, back);
    }

    #[test]
    fn ticket_valido_passa() {
        let b = sample().encode(&key());
        let mut g = MemoryReplayGuard::new(1024);
        let t = verify(&b, &ring(), NOW + 10, &VerifyOptions::default(), &mut g).expect("valido");
        assert!(t.flags.strict());
        assert!(!t.flags.vip());
    }

    #[test]
    fn cada_byte_alterado_quebra_a_assinatura() {
        // Percorre a regiao assinada inteira. Se algum campo ficasse de fora do
        // HMAC por engano, este teste acha - e e exatamente o tipo de erro que
        // passa despercebido numa revisao.
        let base = sample().encode(&key());
        let mut g = MemoryReplayGuard::new(4096);
        for i in 0..TICKET_SIGNED_LEN {
            // O byte reservado nao carrega semantica, mas E assinado.
            let mut b = base;
            b[i] ^= 0xFF;
            let r = verify(&b, &ring(), NOW + 10, &VerifyOptions::default(), &mut g);
            assert!(r.is_err(), "byte {} passou sem ser notado", i);
        }
    }

    #[test]
    fn hmac_adulterado_e_recusado() {
        let mut b = sample().encode(&key());
        b[OFF_HMAC] ^= 0x01;
        let mut g = MemoryReplayGuard::new(16);
        assert_eq!(
            verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::BadSignature
        );
    }

    #[test]
    fn expirado() {
        let b = sample().encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        let t = NOW + TICKET_DEFAULT_TTL_MS as u64 + 1;
        assert_eq!(
            verify(&b, &ring(), t, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::Expired
        );
    }

    #[test]
    fn na_borda_exata_ainda_vale() {
        let b = sample().encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        let t = NOW + TICKET_DEFAULT_TTL_MS as u64;
        assert!(verify(&b, &ring(), t, &VerifyOptions::default(), &mut g).is_ok());
    }

    #[test]
    fn emitido_no_futuro_alem_da_tolerancia() {
        let b = sample().encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        let t = NOW - TICKET_CLOCK_SKEW_MS - 1;
        assert_eq!(
            verify(&b, &ring(), t, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::NotYetValid
        );
        // dentro da tolerancia, passa
        let mut g2 = MemoryReplayGuard::new(16);
        assert!(verify(&b, &ring(), NOW - TICKET_CLOCK_SKEW_MS, &VerifyOptions::default(), &mut g2).is_ok());
    }

    #[test]
    fn replay_e_barrado_na_segunda_vez() {
        let b = sample().encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        assert!(verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).is_ok());
        assert_eq!(
            verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::Replay
        );
    }

    #[test]
    fn assinatura_invalida_nao_suja_o_cache_de_replay() {
        // Este e o teste que protege contra encher a memoria do login-server
        // com nonces de tickets forjados.
        let mut g = MemoryReplayGuard::new(64);
        let mut b = sample().encode(&key());
        b[OFF_HMAC + 5] ^= 0xFF;
        for _ in 0..50 {
            let _ = verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g);
        }
        assert_eq!(g.len(), 0, "nonce de ticket invalido entrou no cache");
    }

    #[test]
    fn key_id_desconhecido() {
        let mut t = sample();
        t.key_id = 9;
        let b = t.encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        assert_eq!(
            verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::UnknownKey
        );
    }

    #[test]
    fn rotacao_de_chave_aceita_as_duas() {
        let mut set = KeyRingSet::new();
        set.insert(1, Key::from_bytes([0x42; KEY_LEN]));
        set.insert(2, Key::from_bytes([0x99; KEY_LEN]));

        let mut a = sample();
        a.key_id = 1;
        let ba = a.encode(&Key::from_bytes([0x42; KEY_LEN]));

        let mut b = sample();
        b.key_id = 2;
        b.nonce = [0x77; TICKET_NONCE_LEN];
        let bb = b.encode(&Key::from_bytes([0x99; KEY_LEN]));

        let mut g = MemoryReplayGuard::new(16);
        assert!(verify(&ba, &set, NOW, &VerifyOptions::default(), &mut g).is_ok());
        assert!(verify(&bb, &set, NOW, &VerifyOptions::default(), &mut g).is_ok());

        // depois de aposentar a chave 1, o ticket antigo para de valer
        set.remove(1);
        let mut a2 = sample();
        a2.key_id = 1;
        a2.nonce = [0x55; TICKET_NONCE_LEN];
        let ba2 = a2.encode(&Key::from_bytes([0x42; KEY_LEN]));
        assert_eq!(
            verify(&ba2, &set, NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::UnknownKey
        );
    }

    #[test]
    fn tamanho_e_magic_errados() {
        let mut g = MemoryReplayGuard::new(16);
        assert_eq!(
            verify(&[0u8; 10], &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::InvalidLength
        );
        let mut b = sample().encode(&key());
        b[0] = b'X';
        assert_eq!(
            verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::BadMagic
        );
    }

    #[test]
    fn versao_desconhecida() {
        let mut t = sample();
        t.version = 9;
        let b = t.encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        assert_eq!(
            verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::BadVersion
        );
    }

    #[test]
    fn ttl_absurdo_e_recusado_antes_do_hmac() {
        let mut t = sample();
        t.ttl_ms = 86_400_000; // um dia
        let b = t.encode(&key());
        let mut g = MemoryReplayGuard::new(16);
        assert_eq!(
            verify(&b, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::BadTtl
        );

        let mut t0 = sample();
        t0.ttl_ms = 0;
        let b0 = t0.encode(&key());
        assert_eq!(
            verify(&b0, &ring(), NOW, &VerifyOptions::default(), &mut g).unwrap_err(),
            TicketError::BadTtl
        );
    }

    #[test]
    fn packet_0x0aaa_ida_e_volta() {
        let b = sample().encode(&key());
        let p = encode_login_packet(&b);
        assert_eq!(p.len(), 152);
        assert_eq!(u16::from_le_bytes([p[0], p[1]]), 0x0AAA);
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 152);
        assert_eq!(parse_login_packet(&p).expect("parse"), &b[..]);

        // com outro packet colado atras, ainda le so o proprio
        let mut com_sobra = p.to_vec();
        com_sobra.extend_from_slice(&[0x64, 0x00, 0xAA, 0xBB]);
        assert_eq!(parse_login_packet(&com_sobra).expect("parse"), &b[..]);

        // header de outro packet
        let mut errado = p;
        errado[0] = 0x64;
        errado[1] = 0x00;
        assert!(parse_login_packet(&errado).is_err());
    }

    #[test]
    fn issue_sorteia_nonces_diferentes() {
        let mut rng = TestOnlySeededRandom::new(7);
        let a = RseTicket::issue(
            &mut rng,
            TicketFlags::empty(),
            1,
            NOW,
            TICKET_DEFAULT_TTL_MS,
            [0; SESSION_ID_LEN],
            [0; FINGERPRINT_LEN],
            [0; 32],
        )
        .expect("issue");
        let b = RseTicket::issue(
            &mut rng,
            TicketFlags::empty(),
            1,
            NOW,
            TICKET_DEFAULT_TTL_MS,
            [0; SESSION_ID_LEN],
            [0; FINGERPRINT_LEN],
            [0; 32],
        )
        .expect("issue");
        assert_ne!(a.nonce, b.nonce);
    }
}
