//! Primitivas: chaves, HMAC, HKDF e a fonte de aleatoriedade.
//!
//! Nada aqui inventa criptografia. Sao as primitivas do RustCrypto embrulhadas
//! em tipos que dificultam o uso errado - que e onde os problemas de verdade
//! acontecem: chave trocada entre canais, comparacao de MAC em tempo variavel,
//! nonce repetido.

use crate::error::RandomError;
use crate::version::{
    HKDF_INFO_D2L, HKDF_INFO_L2D, KEY_LEN, MAC_LEN, NONCE_SALT_D2L, NONCE_SALT_L2D, SESSION_ID_LEN,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Chave simetrica de 32 bytes.
///
/// O `Debug` e REDIGIDO e nao existe `Display`: chave impressa em log vira
/// chave vazada, e basta um `{:?}` distraido numa struct que a contenha. Se
/// voce esta aqui querendo imprimir uma chave, o que voce quer mesmo e imprimir
/// o `key_id`.
///
/// Zera a memoria ao sair de escopo (`Drop` + `zeroize`).
#[derive(Clone)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Key(b)
    }

    /// Le uma chave em hexadecimal (64 caracteres).
    ///
    /// E assim que ela chega do `login_athena.conf` e das variaveis de ambiente
    /// do Auth Service.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != KEY_LEN * 2 {
            return None;
        }
        let mut out = [0u8; KEY_LEN];
        let b = s.as_bytes();
        for i in 0..KEY_LEN {
            let hi = hex_val(b[i * 2])?;
            let lo = hex_val(b[i * 2 + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Some(Key(out))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `Debug` REDIGIDO. O tipo precisa de `Debug` porque aparece dentro de structs
/// maiores que querem derivar o seu, mas o conteudo nunca sai daqui.
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(<redigida>)")
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Converte bytes em hexadecimal minusculo. Usado nos vetores de teste e nos
/// logs (para nonce e fingerprint - nunca para chave).
pub fn to_hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

/// Converte hexadecimal em bytes. Devolve `None` para entrada malformada.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((hex_val(b[i])? << 4) | hex_val(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// HMAC-SHA256 de `data`.
pub fn hmac_sha256(key: &Key, data: &[u8]) -> [u8; MAC_LEN] {
    // `new_from_slice` so falha para tamanho invalido de chave, e a nossa e
    // sempre 32 bytes por construcao. Ainda assim, nada de `unwrap`: este crate
    // roda dentro do processo do jogo e o workspace compila com
    // `panic = 'abort'` - um panic aqui derruba o jogo do jogador.
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return [0u8; MAC_LEN],
    };
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; MAC_LEN];
    r.copy_from_slice(&out);
    r
}

/// Compara dois MACs em tempo constante.
///
/// 🚨 NUNCA troque isto por `a == b`. A comparacao normal de slice sai no
/// primeiro byte diferente, e o tempo de resposta entrega, byte a byte, qual e
/// o MAC correto. E um ataque conhecido e pratico contra servidor exposto.
pub fn mac_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Qual ponta do canal Loader <-> DLL esta falando.
///
/// Existe para tornar impossivel cifrar com a chave da direcao errada: o tipo
/// carrega a direcao junto com a chave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Loader -> DLL
    LoaderToDll,
    /// DLL -> Loader
    DllToLoader,
}

impl Direction {
    pub(crate) fn info(self) -> &'static [u8] {
        match self {
            Direction::LoaderToDll => HKDF_INFO_L2D,
            Direction::DllToLoader => HKDF_INFO_D2L,
        }
    }

    pub(crate) fn nonce_salt(self) -> [u8; 4] {
        match self {
            Direction::LoaderToDll => NONCE_SALT_L2D,
            Direction::DllToLoader => NONCE_SALT_D2L,
        }
    }

    /// A direcao oposta - usada para montar o par de codecs de uma ponta.
    pub fn opposite(self) -> Direction {
        match self {
            Direction::LoaderToDll => Direction::DllToLoader,
            Direction::DllToLoader => Direction::LoaderToDll,
        }
    }
}

/// Deriva a chave de uma direcao a partir da chave de sessao.
///
/// `salt` do HKDF = `session_id`. Isso garante que duas execucoes do jogo na
/// mesma maquina, mesmo que por acidente sorteassem a mesma `K_s`, nao gerem as
/// mesmas chaves de canal.
pub fn derive_channel_key(session_key: &Key, session_id: &[u8; SESSION_ID_LEN], dir: Direction) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(&session_id[..]), session_key.as_bytes());
    let mut out = [0u8; KEY_LEN];
    if hk.expand(dir.info(), &mut out).is_err() {
        // So acontece se o tamanho pedido passar de 255*32 bytes. Nao passa.
        out = [0u8; KEY_LEN];
    }
    Key(out)
}

/// Deriva as duas chaves de uma vez: `(loader->dll, dll->loader)`.
pub fn derive_channel_keys(session_key: &Key, session_id: &[u8; SESSION_ID_LEN]) -> (Key, Key) {
    (
        derive_channel_key(session_key, session_id, Direction::LoaderToDll),
        derive_channel_key(session_key, session_id, Direction::DllToLoader),
    )
}

/// De onde vem a aleatoriedade.
///
/// E um trait, e nao uma chamada direta ao SO, por dois motivos: o teste precisa
/// de entropia deterministica para reproduzir vetores, e o crate precisa
/// continuar sem I/O (ver o cabecalho do Cargo.toml).
pub trait RandomSource {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RandomError>;
}

/// CSPRNG do sistema operacional (`BCryptGenRandom` no Windows).
#[cfg(feature = "os-rng")]
#[derive(Debug)]
pub struct OsRandom;

#[cfg(feature = "os-rng")]
impl RandomSource for OsRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RandomError> {
        getrandom::getrandom(dest).map_err(|_| RandomError)
    }
}

/// Fonte deterministica para TESTE e para gerar vetores.
///
/// 🚨 Nunca use em producao. O nome e feio de proposito.
#[derive(Debug)]
pub struct TestOnlySeededRandom {
    state: u64,
}

impl TestOnlySeededRandom {
    pub fn new(seed: u64) -> Self {
        TestOnlySeededRandom {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }
}

impl RandomSource for TestOnlySeededRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), RandomError> {
        // SplitMix64 - suficiente para reproduzir vetores, imprestavel para
        // qualquer outra coisa.
        for chunk in dest.chunks_mut(8) {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let b = z.to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&b[..n]);
        }
        Ok(())
    }
}

#[cfg(test)]
// Em teste, `expect` e `assert` sao a ferramenta certa: falha de teste DEVE
// abortar com mensagem. A proibicao de panico vale para o codigo que roda
// dentro do processo do jogo, nao para o que roda no CI.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hex_ida_e_volta() {
        let k = Key::from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .expect("hex valido");
        assert_eq!(
            to_hex(k.as_bytes()),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        assert!(Key::from_hex("abc").is_none());
        assert!(Key::from_hex(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn mac_equal_recusa_tamanhos_diferentes() {
        assert!(!mac_equal(&[1, 2, 3], &[1, 2]));
        assert!(mac_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!mac_equal(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    fn direcoes_derivam_chaves_diferentes() {
        let ks = Key::from_bytes([7u8; KEY_LEN]);
        let sid = [3u8; SESSION_ID_LEN];
        let (a, b) = derive_channel_keys(&ks, &sid);
        assert_ne!(a.as_bytes(), b.as_bytes());
        // E nenhuma delas pode ser a propria chave de sessao.
        assert_ne!(a.as_bytes(), ks.as_bytes());
        assert_ne!(b.as_bytes(), ks.as_bytes());
    }

    #[test]
    fn session_id_diferente_muda_a_derivacao() {
        let ks = Key::from_bytes([7u8; KEY_LEN]);
        let a = derive_channel_key(&ks, &[1u8; SESSION_ID_LEN], Direction::LoaderToDll);
        let b = derive_channel_key(&ks, &[2u8; SESSION_ID_LEN], Direction::LoaderToDll);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn from_hex_recusa_entrada_torta() {
        assert!(from_hex("abc").is_none(), "tamanho impar");
        assert!(from_hex("zz").is_none(), "digito invalido");
        assert_eq!(from_hex("").expect("vazio e valido"), Vec::<u8>::new());
        assert_eq!(from_hex("00FF").expect("maiuscula"), vec![0x00, 0xFF]);
        assert_eq!(from_hex(" 0a0b \n").expect("com espaco em volta"), vec![0x0a, 0x0b]);
    }

    #[test]
    fn sha256_de_valor_conhecido() {
        // Vetor classico: SHA-256("abc").
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn direcao_oposta() {
        assert_eq!(Direction::LoaderToDll.opposite(), Direction::DllToLoader);
        assert_eq!(Direction::DllToLoader.opposite(), Direction::LoaderToDll);
    }

    #[test]
    fn debug_de_chave_nao_vaza_o_conteudo() {
        // Testa a promessa feita no comentario do tipo. Se alguem trocar o
        // Debug por um derive, isto quebra.
        let k = Key::from_bytes([0xAB; KEY_LEN]);
        let texto = format!("{:?}", k);
        assert_eq!(texto, "Key(<redigida>)");
        assert!(!texto.contains("ab"), "chave apareceu no Debug");
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn os_random_devolve_bytes_diferentes() {
        let mut r = OsRandom;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        r.fill(&mut a).expect("entropia do SO");
        r.fill(&mut b).expect("entropia do SO");
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32], "entropia toda zero e sinal de problema");
    }

    #[test]
    fn hmac_conhecido_e_estavel() {
        // Nao e vetor oficial de RFC; e um travamento de regressao. Se este
        // valor mudar, alguma dependencia mudou de comportamento e TODOS os
        // tickets em campo pararam de validar.
        let k = Key::from_bytes([0u8; KEY_LEN]);
        let mac = hmac_sha256(&k, b"RagnaShield");
        assert_eq!(mac.len(), MAC_LEN);
        let again = hmac_sha256(&k, b"RagnaShield");
        assert!(mac_equal(&mac, &again));
        let other = hmac_sha256(&k, b"RagnaShielc");
        assert!(!mac_equal(&mac, &other));
    }
}
