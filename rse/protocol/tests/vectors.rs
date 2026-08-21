//! Conferencia contra os vetores CONGELADOS da versao 1.
//!
//! Estes testes pegam uma classe especifica de acidente: alguem mexe no codigo,
//! todos os testes de unidade continuam verdes - porque eles testam o codigo
//! contra ele mesmo - e o formato na fita mudou. Em campo isso aparece como
//! "os jogadores pararam de entrar depois da atualizacao".
//!
//! Aqui os bytes esperados estao gravados em disco. Se a implementacao mudar o
//! formato, isto quebra. Regravar `vectors.txt` para "consertar" o teste e a
//! coisa errada a fazer - a menos que a mudanca seja intencional E o
//! `RSE_PROTOCOL` tenha sido incrementado junto.
//!
//! O leitor abaixo tem umas 30 linhas e nenhuma dependencia. E de proposito: o
//! mesmo arquivo vai ser lido em C++ na Fase 3, e um formato que exige
//! biblioteca de terceiros para ler seria um empecilho bobo.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rse_protocol::crypto::{derive_channel_keys, from_hex, to_hex, Direction, Key};
use rse_protocol::frame::{Opcode, Opener, Sealer};
use rse_protocol::replay::MemoryReplayGuard;
use rse_protocol::ticket::{parse_login_packet, verify, SingleKey, VerifyOptions};
use rse_protocol::version::*;

const BRUTO: &str = include_str!("vectors/v1/vectors.txt");

/// Um registro do arquivo: o tipo (`@ticket`, `@frame`, ...) e os pares chave=valor.
struct Registro<'a> {
    tipo: &'a str,
    campos: Vec<(&'a str, &'a str)>,
}

impl<'a> Registro<'a> {
    fn get(&self, chave: &str) -> &'a str {
        self.campos
            .iter()
            .find(|(k, _)| *k == chave)
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("registro {} sem o campo '{}'", self.tipo, chave))
    }
    fn num(&self, chave: &str) -> u64 {
        self.get(chave)
            .parse()
            .unwrap_or_else(|_| panic!("campo '{}' nao e numero", chave))
    }
    /// Bytes em hexadecimal. `-` representa vazio (payload de tamanho zero).
    fn bytes(&self, chave: &str) -> Vec<u8> {
        let v = self.get(chave);
        if v == "-" {
            return Vec::new();
        }
        from_hex(v).unwrap_or_else(|| panic!("campo '{}' nao e hexadecimal", chave))
    }
}

fn ler(tipo: &str) -> Vec<Registro<'static>> {
    BRUTO
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let t = it.next()?;
            if t != tipo {
                return None;
            }
            let campos = it
                .filter_map(|p| {
                    let mut kv = p.splitn(2, '=');
                    Some((kv.next()?, kv.next()?))
                })
                .collect();
            Some(Registro { tipo: t, campos })
        })
        .collect()
}

fn chave32(hexa: &str) -> Key {
    let b = from_hex(hexa).expect("hexadecimal valido");
    assert_eq!(b.len(), KEY_LEN, "chave com tamanho errado");
    let mut a = [0u8; KEY_LEN];
    a.copy_from_slice(&b);
    Key::from_bytes(a)
}

fn sid16(hexa: &str) -> [u8; SESSION_ID_LEN] {
    let b = from_hex(hexa).expect("hexadecimal valido");
    assert_eq!(b.len(), SESSION_ID_LEN);
    let mut a = [0u8; SESSION_ID_LEN];
    a.copy_from_slice(&b);
    a
}

#[test]
fn meta_declara_os_mesmos_numeros_do_codigo() {
    let metas = ler("@meta");
    assert!(!metas.is_empty(), "arquivo sem @meta");
    let m = &metas[0];
    assert_eq!(m.num("protocol"), RSE_PROTOCOL as u64);
    assert_eq!(m.num("ticket_len"), TICKET_LEN as u64);
    assert_eq!(m.num("ticket_signed_len"), TICKET_SIGNED_LEN as u64);
    assert_eq!(m.num("mac_len"), MAC_LEN as u64);
    assert_eq!(m.num("clock_skew_ms"), TICKET_CLOCK_SKEW_MS);
    assert_eq!(m.num("max_ttl_ms"), TICKET_MAX_TTL_MS as u64);
    assert_eq!(m.num("default_ttl_ms"), TICKET_DEFAULT_TTL_MS as u64);

    let o = &metas[1];
    assert_eq!(o.num("off_magic"), OFF_MAGIC as u64);
    assert_eq!(o.num("off_version"), OFF_VERSION as u64);
    assert_eq!(o.num("off_flags"), OFF_FLAGS as u64);
    assert_eq!(o.num("off_key_id"), OFF_KEY_ID as u64);
    assert_eq!(o.num("off_issued_at"), OFF_ISSUED_AT as u64);
    assert_eq!(o.num("off_ttl"), OFF_TTL as u64);
    assert_eq!(o.num("off_nonce"), OFF_NONCE as u64);
    assert_eq!(o.num("off_session_id"), OFF_SESSION_ID as u64);
    assert_eq!(o.num("off_machine_fp"), OFF_MACHINE_FP as u64);
    assert_eq!(o.num("off_client_hash"), OFF_CLIENT_HASH as u64);
    assert_eq!(o.num("off_hmac"), OFF_HMAC as u64);
}

#[test]
fn todos_os_casos_de_ticket_dao_o_resultado_congelado() {
    let k = ler("@key");
    let anel = SingleKey::new(k[0].num("id") as u8, chave32(k[0].get("hex")));

    let casos = ler("@ticket");
    assert!(casos.len() >= 12, "poucos casos: {}", casos.len());

    for c in &casos {
        let nome = c.get("name");
        let bytes = c.bytes("hex");
        let agora = c.num("now_ms");
        let esperado = c.get("expect");
        let duas_vezes = c.num("twice") == 1;

        let mut guarda = MemoryReplayGuard::new(256);
        let mut r = verify(&bytes, &anel, agora, &VerifyOptions::default(), &mut guarda);
        if duas_vezes {
            r = verify(&bytes, &anel, agora, &VerifyOptions::default(), &mut guarda);
        }
        let obtido = match &r {
            Ok(_) => "OK",
            Err(e) => e.label(),
        };
        assert_eq!(
            obtido, esperado,
            "caso '{}': esperado {}, obtido {}",
            nome, esperado, obtido
        );
    }
}

#[test]
fn cobre_todos_os_resultados_previstos_no_spec() {
    // Se um codigo de erro novo entrar no protocolo sem ganhar vetor, isto
    // avisa agora - e nao seis meses depois, quando o C++ divergir nele.
    let casos = ler("@ticket");
    let vistos: Vec<&str> = casos.iter().map(|c| c.get("expect")).collect();
    for exigido in [
        "OK",
        "INVALID_LENGTH",
        "BAD_MAGIC",
        "BAD_VERSION",
        "UNKNOWN_KEY",
        "BAD_SIGNATURE",
        "EXPIRED",
        "FUTURE",
        "REPLAY",
        "BAD_TTL",
    ] {
        assert!(
            vistos.contains(&exigido),
            "nenhum vetor cobre o resultado '{}'",
            exigido
        );
    }
}

#[test]
fn packet_0x0aaa_congelado_ainda_e_lido() {
    let p = ler("@packet");
    let r = &p[0];
    assert_eq!(r.num("id"), LOGIN_PACKET_ID as u64);
    assert_eq!(r.num("len"), LOGIN_PACKET_LEN as u64);

    let bytes = r.bytes("hex");
    assert_eq!(bytes.len(), LOGIN_PACKET_LEN);
    let ticket = parse_login_packet(&bytes).expect("packet valido");

    let primeiro = ler("@ticket")[0].bytes("hex");
    assert_eq!(ticket, &primeiro[..]);
}

#[test]
fn derivacao_de_chaves_do_canal_bate_com_o_congelado() {
    let c = &ler("@canal")[0];
    let ks = chave32(c.get("session_key"));
    let sid = sid16(c.get("session_id"));

    let (l2d, d2l) = derive_channel_keys(&ks, &sid);
    assert_eq!(to_hex(l2d.as_bytes()), c.get("k_l2d"), "HKDF loader->dll mudou");
    assert_eq!(to_hex(d2l.as_bytes()), c.get("k_d2l"), "HKDF dll->loader mudou");
}

#[test]
fn frames_congelados_sao_reproduzidos_byte_a_byte() {
    let c = &ler("@canal")[0];
    let ks = chave32(c.get("session_key"));
    let sid = sid16(c.get("session_id"));
    let (l2d, _) = derive_channel_keys(&ks, &sid);

    let mut selador = Sealer::new(&l2d, Direction::LoaderToDll);
    let frames = ler("@frame");
    assert!(frames.len() >= 5, "poucos frames: {}", frames.len());

    for f in &frames {
        let nome = f.get("name");
        let opcode = Opcode::from_u8(f.num("opcode") as u8)
            .unwrap_or_else(|_| panic!("opcode desconhecido no vetor '{}'", nome));
        let payload = f.bytes("payload");
        assert_eq!(payload.len() as u64, f.num("payload_len"), "payload_len de '{}'", nome);
        assert_eq!(selador.next_seq() as u64, f.num("seq"), "seq divergiu em '{}'", nome);

        let saiu = selador.seal(opcode, &payload).expect("seal");
        assert_eq!(to_hex(&saiu), f.get("frame"), "frame '{}' mudou de bytes", nome);
    }
}

#[test]
fn frames_congelados_abrem_e_devolvem_o_payload() {
    let c = &ler("@canal")[0];
    let ks = chave32(c.get("session_key"));
    let sid = sid16(c.get("session_id"));
    let (l2d, _) = derive_channel_keys(&ks, &sid);

    let mut abridor = Opener::new(&l2d, Direction::LoaderToDll);
    for f in &ler("@frame") {
        let nome = f.get("name");
        let bytes = f.bytes("frame");
        let aberto = abridor
            .open(&bytes)
            .unwrap_or_else(|e| panic!("frame '{}' nao abriu: {}", nome, e));
        assert_eq!(aberto.payload, f.bytes("payload"), "payload de '{}'", nome);
        assert_eq!(aberto.seq as u64, f.num("seq"));
    }
}

#[test]
fn sequencia_fora_de_ordem_e_recusada_nos_vetores() {
    let c = &ler("@canal")[0];
    let ks = chave32(c.get("session_key"));
    let sid = sid16(c.get("session_id"));
    let (l2d, _) = derive_channel_keys(&ks, &sid);

    let frames = ler("@frame");
    let f1 = frames[0].bytes("frame");
    let f2 = frames[1].bytes("frame");
    let f3 = frames[2].bytes("frame");

    let mut abridor = Opener::new(&l2d, Direction::LoaderToDll);
    assert!(abridor.open(&f1).is_ok(), "frame 1");
    assert!(abridor.open(&f3).is_ok(), "pular pra frente e permitido");
    let e = abridor.open(&f2).expect_err("voltar no seq tem que reprovar");
    assert_eq!(e.label(), "REPLAYED_SEQUENCE");
}
