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

/// Payload do `TICKET_RSP` (Loader -> DLL): a resposta ao pedido de ticket fresco.
///
/// ```text
/// offset  tam  campo
///      0    1  status (0 = ok, seguem 148 bytes; != 0 = falha, sem ticket)
///      1  148  ticket, so quando status == 0
/// ```
///
/// # Por que um ticket FRESCO, e não o do HELLO
///
/// O ticket vale 30 s (spec §4.2), e é pedido no clique em JOGAR. Se o jogador
/// demora para digitar a senha, o ticket do arranque expira antes do login. A
/// DLL então pede um ticket novo pelo canal a cada ~15 s até o login sair, e o
/// netgate sempre tem um recente na mão. O `send` do hook é síncrono e não pode
/// esperar uma volta ao servidor — por isso o ticket tem que estar pronto ANTES.
pub const TICKET_RSP_OK_LEN: usize = 1 + 148;

pub fn montar_ticket_rsp_ok(ticket: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(TICKET_RSP_OK_LEN);
    p.push(0); // status ok
    p.extend_from_slice(ticket);
    p
}

pub fn montar_ticket_rsp_falha() -> [u8; 1] {
    [1] // status != 0
}

/// Devolve o ticket se o status for ok e o tamanho bater; senão `None`.
pub fn ler_ticket_rsp(p: &[u8], ticket_len: usize) -> Option<&[u8]> {
    if p.is_empty() || p[0] != 0 {
        return None;
    }
    if p.len() < 1 + ticket_len {
        return None;
    }
    Some(&p[1..1 + ticket_len])
}

// ---- REPORT / REPORT_ACK (Fase 5c) ----------------------------------------
//
// Payload do REPORT: texto UTF-8, uma violação por linha, campos separados por
// `|`: `code|severity|detail`. Formato simples de propósito — o Loader precisa
// só quebrar em linhas e repassar ao `/report`, sem parser pesado. `code` é
// numérico (RSE_SPEC §9); `detail` não contém `\n` nem `|`.
pub fn montar_report(linhas: &[String]) -> Vec<u8> {
    linhas.join("\n").into_bytes()
}

/// `6040` — o relatório não coube inteiro e parte dele foi descartada.
///
/// Severidade **alta**, e não informativa, de propósito: perder achado não é
/// rotina. Quem lê o log precisa saber que está vendo uma amostra, não o todo.
const COD_RELATORIO_TRUNCADO: u16 = 6040;

/// Quebra as linhas de um REPORT em lotes que caibam no frame.
///
/// # O bug que isto conserta
///
/// `montar_report` junta tudo num payload só. O frame tem teto de
/// `FRAME_MAX_PAYLOAD` (8192 B), e o `seal` **recusa** o que passa disso. O
/// caminho de erro no `canal.rs` apenas registrava localmente — então um
/// relatório grande demais **sumia inteiro** a caminho do servidor.
///
/// Aconteceu de verdade na primeira varredura da Fase 6.4b: 95 achados, 9335
/// bytes, `PAYLOAD_TOO_LARGE`, e o servidor não recebeu nem os 95 nem o achado
/// que interessava, que estava no meio deles.
///
/// O modo de falhar é perverso e vale nomear: **era tudo ou nada, e piorava
/// quanto pior a situação**. Um cliente com 100 arquivos adulterados — o caso
/// mais grave que existe — geraria o maior relatório, estouraria o teto, e o
/// servidor veria silêncio. Quanto mais havia para contar, menos chegava.
///
/// # As três garantias
///
/// 1. **Nada some calado.** Se algo não couber, a última linha diz quantos
///    ficaram de fora (`6040`), e ela mesma cabe no lote.
/// 2. **Todo lote cabe.** Nenhum payload devolvido passa de `teto`.
/// 3. **Linha gigante é cortada, não descartada.** Um `detail` absurdo vira uma
///    linha truncada com `…` — sinal de que existe algo estranho ali, que é
///    justamente o que não se quer perder.
///
/// `max_lotes` limita quantos frames uma varredura pode gerar: sem ele, uma
/// máquina com milhares de achados inundaria o pipe a cada 60 s.
pub fn lotes_de_report(linhas: &[String], teto: usize, max_lotes: usize) -> Vec<Vec<u8>> {
    if linhas.is_empty() || teto == 0 || max_lotes == 0 {
        return Vec::new();
    }

    // Corta o que não cabe nem sozinho numa linha. O `-1` deixa espaço para o
    // separador que virá depois dela.
    let cortadas: Vec<String> = linhas
        .iter()
        .map(|l| {
            if l.len() <= teto {
                l.clone()
            } else {
                let mut s = cortar_utf8(l, teto.saturating_sub(3));
                s.push('…');
                s
            }
        })
        .collect();

    let mut lotes: Vec<Vec<u8>> = Vec::new();
    let mut atual: Vec<&str> = Vec::new();
    let mut tam = 0usize;
    let mut i = 0usize;

    while i < cortadas.len() {
        let l = cortadas[i].as_str();
        // +1 pelo `\n` que separa desta linha da anterior.
        let custo = if atual.is_empty() { l.len() } else { l.len() + 1 };

        if tam + custo <= teto {
            tam += custo;
            atual.push(l);
            i += 1;
            continue;
        }

        // Não coube: fecha o lote atual.
        lotes.push(atual.join("\n").into_bytes());
        atual.clear();
        tam = 0;

        if lotes.len() >= max_lotes {
            break; // o resto vira aviso, abaixo
        }
    }

    if !atual.is_empty() && lotes.len() < max_lotes {
        lotes.push(atual.join("\n").into_bytes());
        atual.clear();
        i = cortadas.len();
    }

    // Sobrou coisa sem lote? Avisa quantas, dentro do último lote.
    let de_fora = cortadas.len().saturating_sub(i) + atual.len();
    if de_fora > 0 {
        let aviso = format!(
            "{}|alta|relatorio truncado: {} linha(s) nao couberam",
            COD_RELATORIO_TRUNCADO, de_fora
        );
        encaixar_aviso(&mut lotes, aviso, teto);
    }

    lotes
}

/// Põe o aviso no último lote, abrindo espaço se preciso.
///
/// Se nem removendo linhas o aviso couber (lote de teto minúsculo), ele vira um
/// lote próprio — porque a informação "faltou coisa" vale mais do que a última
/// linha de achado.
fn encaixar_aviso(lotes: &mut Vec<Vec<u8>>, aviso: String, teto: usize) {
    if aviso.len() > teto {
        return; // teto absurdo; nada a fazer sem estourar a garantia 2
    }
    if let Some(ultimo) = lotes.last_mut() {
        while !ultimo.is_empty() && ultimo.len() + 1 + aviso.len() > teto {
            // Remove a última linha do lote para abrir espaço.
            match ultimo.iter().rposition(|b| *b == b'\n') {
                Some(p) => ultimo.truncate(p),
                None => ultimo.clear(),
            }
        }
        if ultimo.is_empty() {
            *ultimo = aviso.into_bytes();
        } else {
            ultimo.push(b'\n');
            ultimo.extend_from_slice(aviso.as_bytes());
        }
    } else {
        lotes.push(aviso.into_bytes());
    }
}

/// Corta uma string em no máximo `max` bytes sem partir um caractere UTF-8.
///
/// Cortar por byte numa string com acento produziria bytes inválidos — e o
/// `detail` de uma violação frequentemente traz nome de arquivo com acento.
fn cortar_utf8(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut fim = max;
    while fim > 0 && !s.is_char_boundary(fim) {
        fim -= 1;
    }
    s[..fim].to_string()
}

/// Lê o REPORT_ACK: a ação que o servidor decidiu, em texto ("report"/"kill"/…).
pub fn ler_report_ack(p: &[u8]) -> String {
    String::from_utf8_lossy(p).trim().to_string()
}

#[cfg(test)]
mod tests {
    // ---- lotes_de_report (o conserto do PAYLOAD_TOO_LARGE) ----------------

    const TETO: usize = 8192;

    fn linhas_falsas(n: usize, tam: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let mut s = format!("3003|alta|dono numero {} ", i);
                while s.len() < tam {
                    s.push('x');
                }
                s.truncate(tam);
                s
            })
            .collect()
    }

    fn tudo_cabe(lotes: &[Vec<u8>], teto: usize) {
        for (i, l) in lotes.iter().enumerate() {
            assert!(
                l.len() <= teto,
                "lote {} tem {} bytes, acima do teto {}",
                i,
                l.len(),
                teto
            );
        }
    }

    #[test]
    fn vazio_nao_gera_lote() {
        assert!(lotes_de_report(&[], TETO, 4).is_empty());
    }

    #[test]
    fn o_que_cabe_vira_um_lote_so() {
        let v = linhas_falsas(10, 97);
        let lotes = lotes_de_report(&v, TETO, 4);
        assert_eq!(lotes.len(), 1);
        tudo_cabe(&lotes, TETO);
        let texto = String::from_utf8(lotes[0].clone()).unwrap();
        assert_eq!(texto.lines().count(), 10);
    }

    /// O caso REAL que quebrou: 95 achados de ~97 bytes = 9335 bytes.
    #[test]
    fn o_caso_de_95_achados_que_estourava_agora_passa() {
        let v = linhas_falsas(95, 97);
        let bruto: usize = v.iter().map(|l| l.len()).sum::<usize>() + v.len() - 1;
        assert!(bruto > TETO, "o cenario precisa estourar: {} bytes", bruto);

        let lotes = lotes_de_report(&v, TETO, 4);
        tudo_cabe(&lotes, TETO);
        assert_eq!(lotes.len(), 2, "deve caber em dois frames");

        // NENHUMA linha pode ter sumido.
        let juntos: Vec<String> = lotes
            .iter()
            .flat_map(|l| {
                String::from_utf8(l.clone())
                    .unwrap()
                    .lines()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(juntos.len(), 95);
        for original in &v {
            assert!(juntos.contains(original), "linha perdida: {}", original);
        }
    }

    #[test]
    fn quando_estoura_o_limite_de_lotes_avisa_quantos_ficaram() {
        let v = linhas_falsas(1000, 97);
        let lotes = lotes_de_report(&v, TETO, 2);
        tudo_cabe(&lotes, TETO);
        assert_eq!(lotes.len(), 2);

        let ultimo = String::from_utf8(lotes[1].clone()).unwrap();
        let fim = ultimo.lines().last().unwrap();
        assert!(
            fim.starts_with("6040|alta|relatorio truncado:"),
            "faltou o aviso; ultima linha = {}",
            fim
        );
        // E o numero tem que ser verdade.
        let entregues: usize = lotes
            .iter()
            .map(|l| String::from_utf8(l.clone()).unwrap().lines().count())
            .sum::<usize>()
            - 1; // o aviso nao e achado
        let anunciados: usize = fim
            .rsplit("truncado: ")
            .next()
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            entregues + anunciados,
            1000,
            "entregues {} + anunciados {} != 1000",
            entregues,
            anunciados
        );
    }

    #[test]
    fn linha_gigante_e_cortada_nao_descartada() {
        let mut gigante = String::from("1000|critica|");
        while gigante.len() < TETO * 3 {
            gigante.push('A');
        }
        let lotes = lotes_de_report(&[gigante], TETO, 4);
        tudo_cabe(&lotes, TETO);
        assert_eq!(lotes.len(), 1);
        let t = String::from_utf8(lotes[0].clone()).unwrap();
        assert!(t.starts_with("1000|critica|"), "perdeu o comeco: {}", &t[..40]);
        assert!(t.ends_with('…'), "faltou a marca de corte");
    }

    #[test]
    fn corte_nao_parte_caractere_acentuado() {
        // 'ç' ocupa 2 bytes; cortar no meio produziria UTF-8 invalido.
        let mut s = String::from("1002|alta|arquivo coraç");
        while s.len() < 60 {
            s.push('ç');
        }
        let lotes = lotes_de_report(&[s], 40, 4);
        tudo_cabe(&lotes, 40);
        // Se o corte partisse um caractere, o from_utf8 abaixo falharia.
        let t = String::from_utf8(lotes[0].clone()).expect("corte gerou UTF-8 invalido");
        assert!(t.ends_with('…'));
    }

    #[test]
    fn teto_apertado_ainda_respeita_o_teto() {
        for teto in [20usize, 50, 120, 300] {
            let v = linhas_falsas(50, 97);
            let lotes = lotes_de_report(&v, teto, 3);
            tudo_cabe(&lotes, teto);
        }
    }

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

    #[test]
    fn ticket_rsp_ok_ida_e_volta() {
        let ticket = [0xABu8; 148];
        let p = montar_ticket_rsp_ok(&ticket);
        assert_eq!(p.len(), TICKET_RSP_OK_LEN);
        assert_eq!(ler_ticket_rsp(&p, 148).unwrap(), &ticket[..]);
    }

    #[test]
    fn ticket_rsp_falha_nao_tem_ticket() {
        assert!(ler_ticket_rsp(&montar_ticket_rsp_falha(), 148).is_none());
    }

    #[test]
    fn ticket_rsp_curto_reprova() {
        let mut p = vec![0u8]; // status ok mas sem ticket
        p.extend_from_slice(&[0u8; 100]); // curto
        assert!(ler_ticket_rsp(&p, 148).is_none());
    }
}
