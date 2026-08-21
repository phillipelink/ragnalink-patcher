//! Gera os vetores de teste congelados da versao 1 do protocolo.
//!
//! ```text
//! cargo run --example gen_vectors -- rse/protocol/tests/vectors/v1/vectors.txt
//! ```
//!
//! 🚨 POR QUE ISTO EXISTE, e por que nao e "so mais um teste":
//!
//! Na Fase 3 o login-server do rAthena vai validar tickets em C++. Duas
//! implementacoes do mesmo formato SEMPRE divergem em algum canto - ordem de
//! bytes de um `u64`, o que exatamente entra no HMAC, se o limite do TTL e
//! `<` ou `<=`. Quando divergem, o sintoma nao e um erro de compilacao: e um
//! jogador que nao consegue entrar, as vezes, e ninguem sabe por que.
//!
//! Estes vetores sao o contrato. Rust gera, C++ tem que reproduzir. Se os dois
//! passam nos mesmos 20 casos, incluindo os negativos, eles concordam sobre o
//! formato.
//!
//! O arquivo gerado e DETERMINISTICO: mesma entrada, mesmos bytes. Rodar de novo
//! sem mudar o codigo nao deve produzir diff nenhum - e se produzir, alguma
//! coisa mudou no protocolo e todo mundo em campo precisa saber.

use rse_protocol::crypto::{derive_channel_keys, to_hex, Key, TestOnlySeededRandom};
use rse_protocol::frame::{Opcode, Sealer};
use rse_protocol::crypto::Direction;
use rse_protocol::replay::MemoryReplayGuard;
use rse_protocol::ticket::{
    encode_login_packet, verify, RseTicket, SingleKey, TicketFlags, VerifyOptions,
};
use rse_protocol::version::*;
use std::fmt::Write as _;

/// Instante fixo: 2027-01-15 12:00:00 UTC, em milissegundos.
const T0: u64 = 1_800_000_000_000;

const K_TICKET: [u8; KEY_LEN] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
];

const K_SESSION: [u8; KEY_LEN] = [0x5A; KEY_LEN];
const SESSION_ID: [u8; SESSION_ID_LEN] = [
    0x3F, 0x2B, 0x10, 0x9C, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01,
];

struct Case {
    name: &'static str,
    why: &'static str,
    now_ms: u64,
    expect: &'static str,
    bytes: Vec<u8>,
    /// Casos marcados assim precisam ser apresentados DUAS vezes ao verificador:
    /// a primeira passa, a segunda tem de dar REPLAY.
    replay_twice: bool,
}

fn base_ticket(rng: &mut TestOnlySeededRandom, flags: TicketFlags, key_id: u8) -> RseTicket {
    // `TestOnlySeededRandom` nunca falha; o `unwrap_or_else` existe so para nao
    // haver um `unwrap` sequer no repositorio, nem em ferramenta auxiliar.
    RseTicket::issue(
        rng,
        flags,
        key_id,
        T0,
        TICKET_DEFAULT_TTL_MS,
        SESSION_ID,
        [0xC3; FINGERPRINT_LEN],
        [0xD4; 32],
    )
    .unwrap_or_else(|_| {
        eprintln!("fonte de entropia de teste falhou - impossivel");
        std::process::exit(1)
    })
}

fn main() {
    let destino = std::env::args().nth(1).unwrap_or_else(|| {
        "rse/protocol/tests/vectors/v1/vectors.txt".to_string()
    });

    let k = Key::from_bytes(K_TICKET);
    let mut rng = TestOnlySeededRandom::new(0x5253_4530_0000_0001);

    let mut casos: Vec<Case> = Vec::new();

    // ---- positivos: tres tickets validos com bandeiras diferentes ----
    for (name, flags) in [
        ("valido_sem_bandeira", TicketFlags::empty()),
        ("valido_strict", TicketFlags::empty().with(TicketFlags::STRICT)),
        (
            "valido_strict_vip_staff",
            TicketFlags::empty()
                .with(TicketFlags::STRICT)
                .with(TicketFlags::VIP)
                .with(TicketFlags::STAFF),
        ),
    ] {
        let t = base_ticket(&mut rng, flags, 1);
        casos.push(Case {
            name,
            why: "ticket bem formado, dentro da validade, nonce inedito",
            now_ms: T0 + 100,
            expect: "OK",
            bytes: t.encode(&k).to_vec(),
            replay_twice: false,
        });
    }

    // ---- um caso por codigo de erro ----

    // INVALID_LENGTH
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    let mut curto = t.encode(&k).to_vec();
    curto.truncate(147);
    casos.push(Case {
        name: "tamanho_147",
        why: "um byte a menos que os 148 exigidos",
        now_ms: T0,
        expect: "INVALID_LENGTH",
        bytes: curto,
        replay_twice: false,
    });

    // BAD_MAGIC
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    let mut m = t.encode(&k).to_vec();
    m[0] = b'X';
    casos.push(Case {
        name: "magic_errado",
        why: "primeiro byte diferente de 'R'",
        now_ms: T0,
        expect: "BAD_MAGIC",
        bytes: m,
        replay_twice: false,
    });

    // BAD_VERSION
    let mut t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    t.version = 9;
    casos.push(Case {
        name: "versao_9",
        why: "versao de protocolo fora da janela aceita",
        now_ms: T0,
        expect: "BAD_VERSION",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // UNKNOWN_KEY
    let mut t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    t.key_id = 7;
    casos.push(Case {
        name: "key_id_desconhecido",
        why: "assinado com uma chave que o verificador nao tem",
        now_ms: T0,
        expect: "UNKNOWN_KEY",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // BAD_SIGNATURE
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    let mut s = t.encode(&k).to_vec();
    s[OFF_HMAC + 31] ^= 0x01;
    casos.push(Case {
        name: "hmac_ultimo_byte_trocado",
        why: "so o bit menos significativo do MAC mudou - tem que reprovar igual",
        now_ms: T0,
        expect: "BAD_SIGNATURE",
        bytes: s,
        replay_twice: false,
    });

    // BAD_SIGNATURE por campo adulterado (o caso que interessa de verdade)
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    let mut s = t.encode(&k).to_vec();
    s[OFF_FLAGS] |= TicketFlags::STAFF;
    casos.push(Case {
        name: "flags_promovido_para_staff",
        why: "tentativa de virar staff editando o byte de bandeiras - o HMAC pega",
        now_ms: T0,
        expect: "BAD_SIGNATURE",
        bytes: s,
        replay_twice: false,
    });

    // EXPIRED
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    casos.push(Case {
        name: "expirado_por_1ms",
        why: "um milissegundo depois de issued_at + ttl",
        now_ms: T0 + TICKET_DEFAULT_TTL_MS as u64 + 1,
        expect: "EXPIRED",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // borda: exatamente no limite ainda vale
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    casos.push(Case {
        name: "borda_exata_do_ttl",
        why: "issued_at + ttl exato: AINDA VALE. E o `<=` que costuma divergir entre implementacoes",
        now_ms: T0 + TICKET_DEFAULT_TTL_MS as u64,
        expect: "OK",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // FUTURE
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    casos.push(Case {
        name: "emitido_no_futuro",
        why: "relogio do emissor adiantado alem da tolerancia de 5 s",
        now_ms: T0 - TICKET_CLOCK_SKEW_MS - 1,
        expect: "FUTURE",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // borda da tolerancia de relogio
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    casos.push(Case {
        name: "borda_da_tolerancia_de_relogio",
        why: "exatamente 5 s adiantado: ainda aceita",
        now_ms: T0 - TICKET_CLOCK_SKEW_MS,
        expect: "OK",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // BAD_TTL
    let mut t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    t.ttl_ms = 86_400_000;
    casos.push(Case {
        name: "ttl_de_um_dia",
        why: "acima do teto - recusado ANTES de olhar o relogio",
        now_ms: T0,
        expect: "BAD_TTL",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    let mut t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    t.ttl_ms = 0;
    casos.push(Case {
        name: "ttl_zero",
        why: "ticket que nasce morto",
        now_ms: T0,
        expect: "BAD_TTL",
        bytes: t.encode(&k).to_vec(),
        replay_twice: false,
    });

    // REPLAY
    let t = base_ticket(&mut rng, TicketFlags::empty(), 1);
    casos.push(Case {
        name: "reenvio_do_mesmo_ticket",
        why: "apresentado duas vezes: a primeira passa, a segunda tem que dar REPLAY",
        now_ms: T0 + 50,
        expect: "REPLAY",
        bytes: t.encode(&k).to_vec(),
        replay_twice: true,
    });

    // ---- monta o arquivo ----
    //
    // 🚨 FORMATO DE TEXTO, e nao JSON, de proposito: quem vai consumir estes
    // vetores do outro lado e o login-server do rAthena, em C++. Ele nao tem
    // parser JSON a mao - traria uma dependencia nova so para ler arquivo de
    // teste. Uma linha por registro, `chave=valor` separado por espaco, resolve
    // com `istringstream` em umas dez linhas.
    //
    //   #                       comentario
    //   @meta   k=v ...         parametros do protocolo
    //   @key    id=N hex=...    chave de assinatura dos vetores
    //   @ticket ...             um caso de validacao
    //   @packet ...             o packet 0x0AAA
    //   @canal  ...             chaves derivadas do canal
    //   @frame  ...             um frame do canal
    //
    // Nenhum valor contem espaco, entao nao existe questao de escape.
    let mut j = String::new();
    let _ = writeln!(j, "# Vetores CONGELADOS do RSE_PROTOCOL {}.", RSE_PROTOCOL);
    let _ = writeln!(j, "# Gerados por rse/protocol/examples/gen_vectors.rs - nao editar a mao.");
    let _ = writeln!(j, "# A implementacao C++ do login-server (Fase 3) tem que reproduzir");
    let _ = writeln!(j, "# exatamente estes resultados, inclusive os casos negativos.");
    let _ = writeln!(j, "#");
    let _ = writeln!(j, "# Formato: uma linha por registro, `chave=valor` separado por espaco.");
    let _ = writeln!(j, "# Bytes sempre em hexadecimal minusculo, sem separador.");
    let _ = writeln!(
        j,
        "@meta protocol={} ticket_len={} ticket_signed_len={} mac_len={} clock_skew_ms={} max_ttl_ms={} default_ttl_ms={}",
        RSE_PROTOCOL, TICKET_LEN, TICKET_SIGNED_LEN, MAC_LEN, TICKET_CLOCK_SKEW_MS, TICKET_MAX_TTL_MS, TICKET_DEFAULT_TTL_MS
    );
    let _ = writeln!(
        j,
        "@meta off_magic={} off_version={} off_flags={} off_key_id={} off_reserved={} off_issued_at={} off_ttl={} off_nonce={} off_session_id={} off_machine_fp={} off_client_hash={} off_hmac={}",
        OFF_MAGIC, OFF_VERSION, OFF_FLAGS, OFF_KEY_ID, OFF_RESERVED, OFF_ISSUED_AT,
        OFF_TTL, OFF_NONCE, OFF_SESSION_ID, OFF_MACHINE_FP, OFF_CLIENT_HASH, OFF_HMAC
    );
    let _ = writeln!(j, "@key id=1 hex={}", to_hex(&K_TICKET));
    let _ = writeln!(j, "#");
    let _ = writeln!(j, "# --- casos de ticket ---");
    let _ = writeln!(j, "# expect=OK significa que verify() aceita; qualquer outro valor e o");
    let _ = writeln!(j, "# rotulo exato do erro. twice=1 manda apresentar o MESMO ticket duas");
    let _ = writeln!(j, "# vezes ao mesmo verificador: o resultado esperado e o da SEGUNDA vez.");
    for c in &casos {
        let _ = writeln!(j, "# {}: {}", c.name, c.why);
        let _ = writeln!(
            j,
            "@ticket name={} now_ms={} twice={} expect={} hex={}",
            c.name,
            c.now_ms,
            if c.replay_twice { 1 } else { 0 },
            c.expect,
            to_hex(&c.bytes)
        );
    }

    // packet 0x0AAA a partir do primeiro ticket valido
    let primeiro: [u8; TICKET_LEN] = {
        let mut a = [0u8; TICKET_LEN];
        a.copy_from_slice(&casos[0].bytes);
        a
    };
    let pkt = encode_login_packet(&primeiro);
    let _ = writeln!(j, "#");
    let _ = writeln!(j, "# --- packet do login-server ---");
    let _ = writeln!(j, "# header e tamanho em LITTLE-endian; o ticket dentro dele e BIG-endian.");
    let _ = writeln!(
        j,
        "@packet id={} len={} hex={}",
        LOGIN_PACKET_ID,
        LOGIN_PACKET_LEN,
        to_hex(&pkt)
    );

    // ---- canal Loader <-> DLL ----
    let ks = Key::from_bytes(K_SESSION);
    let (l2d, d2l) = derive_channel_keys(&ks, &SESSION_ID);
    let _ = writeln!(j, "#");
    let _ = writeln!(j, "# --- canal Loader <-> DLL ---");
    let _ = writeln!(
        j,
        "# HKDF-SHA256(ikm=session_key, salt=session_id, info=\"{}\" / \"{}\")",
        String::from_utf8_lossy(HKDF_INFO_L2D),
        String::from_utf8_lossy(HKDF_INFO_D2L)
    );
    let _ = writeln!(
        j,
        "@canal session_key={} session_id={} k_l2d={} k_d2l={}",
        to_hex(&K_SESSION),
        to_hex(&SESSION_ID),
        to_hex(l2d.as_bytes()),
        to_hex(d2l.as_bytes())
    );

    let mut sealer = Sealer::new(&l2d, Direction::LoaderToDll);
    let amostras: [(&str, Opcode, Vec<u8>); 5] = [
        ("hello_com_politica", Opcode::Hello, b"epoch=7;strict=1".to_vec()),
        ("payload_vazio", Opcode::Heartbeat, Vec::new()),
        ("payload_de_1_byte", Opcode::HeartbeatAck, vec![0x41]),
        ("ticket_rsp_148_bytes", Opcode::TicketRsp, primeiro.to_vec()),
        ("payload_no_teto_8192", Opcode::Policy, vec![0xAB; FRAME_MAX_PAYLOAD]),
    ];
    for (nome, op, payload) in amostras.iter() {
        let seq = sealer.next_seq();
        let f = match sealer.seal(*op, payload) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("falha ao selar '{}': {}", nome, e);
                std::process::exit(1);
            }
        };
        let _ = writeln!(
            j,
            "@frame name={} dir=L2D seq={} opcode={} payload_len={} payload={} frame={}",
            nome,
            seq,
            op.as_u8(),
            payload.len(),
            if payload.is_empty() { "-".to_string() } else { to_hex(payload) },
            to_hex(&f)
        );
    }
    let _ = writeln!(j, "#");
    let _ = writeln!(j, "# Abrir os frames na ordem 1, 3, 2: o terceiro tem que dar REPLAYED_SEQUENCE.");

    // Conferencia final: os proprios vetores tem que passar pelo verificador
    // deste crate. Gerador que emite vetor errado e pior do que nao ter vetor.
    let ring = SingleKey::new(1, Key::from_bytes(K_TICKET));
    for c in &casos {
        let mut g = MemoryReplayGuard::new(256);
        let mut r = verify(&c.bytes, &ring, c.now_ms, &VerifyOptions::default(), &mut g);
        if c.replay_twice {
            r = verify(&c.bytes, &ring, c.now_ms, &VerifyOptions::default(), &mut g);
        }
        let obtido = match &r {
            Ok(_) => "OK".to_string(),
            Err(e) => e.label().to_string(),
        };
        if obtido != c.expect {
            eprintln!(
                "INCOERENCIA no caso '{}': esperado {}, obtido {}",
                c.name, c.expect, obtido
            );
            std::process::exit(1);
        }
    }

    if let Some(dir) = std::path::Path::new(&destino).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::write(&destino, j.as_bytes()) {
        Ok(()) => println!("vetores gravados em {} ({} casos de ticket)", destino, casos.len()),
        Err(e) => {
            eprintln!("falha ao gravar {}: {}", destino, e);
            std::process::exit(1);
        }
    }
}
