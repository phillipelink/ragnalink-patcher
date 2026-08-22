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
use rse_protocol::version::{RSE_PROTOCOL, SESSION_ID_LEN, TICKET_LEN};

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

    // O `apertar_mao` devolve o resultado da integridade porque ela é medida LÁ
    // DENTRO, antes do HELLO_ACK — ver o comentário sobre a janela suspensa.
    let integridade = apertar_mao(&pipe, &mut opener, &mut sealer)?;

    // Só o ENVIO fica aqui: o canal já está de pé e o jogo já foi retomado, então
    // reportar não atrasa ninguém. Falha ao enviar NÃO é fatal.
    enviar_report_integridade(&pipe, &mut sealer, integridade);

    manter_heartbeat(&pipe, &mut opener, &mut sealer)
}

/// Manda o resultado da integridade (medido no `apertar_mao`) no `REPORT`.
/// Best-effort: se o pipe recusar, só registra e segue.
fn enviar_report_integridade(pipe: &sys::Pipe, sealer: &mut Sealer, linhas: Vec<String>) {
    if linhas.is_empty() {
        sys::log_dll("integridade: nada a reportar");
        return;
    }
    let payload = mensagens::montar_report(&linhas);
    match sealer.seal(Opcode::Report, &payload) {
        Ok(frame) => {
            if pipe.escrever(&frame).is_err() {
                sys::log_dll("nao consegui enviar o REPORT de integridade");
            } else {
                sys::log_dll(&format!("REPORT enviado ({} linha(s))", linhas.len()));
            }
        }
        Err(e) => sys::log_dll(&format!("cifrando REPORT: {}", e)),
    }
}

fn apertar_mao(
    pipe: &sys::Pipe,
    opener: &mut Opener,
    sealer: &mut Sealer,
) -> Result<Vec<String>, String> {

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

    // 2. instalar o netgate ANTES do HELLO_ACK.
    //
    // O HELLO traz `[versao(1)][ticket(148)]`. Instalar o hook aqui, antes de
    // confirmar, garante que ele esteja no lugar quando o Loader retomar o jogo
    // (o Loader so retoma DEPOIS do HELLO_ACK). Se a primeira chamada de rede do
    // cliente escapasse antes do hook, o ticket nao iria e o login entraria sem
    // ele.
    //
    // Falha ao instalar NAO impede o HELLO_ACK: durante o rollout (login-server
    // em 'log') e melhor o jogo abrir sem ticket, com o motivo gritado no log da
    // DLL, do que travar o jogador. Vira erro fatal quando a exigencia virar 'on'.
    if hello.payload.len() >= 1 + TICKET_LEN {
        let ticket = &hello.payload[1..1 + TICKET_LEN];
        match crate::netgate::instalar(ticket) {
            Ok(()) => {}
            Err(e) => sys::log_dll(&format!("FALHA ao instalar o netgate: {} (jogo abre sem ticket)", e)),
        }
    } else {
        sys::log_dll(&format!(
            "HELLO sem ticket (payload de {} bytes) — netgate nao instalado",
            hello.payload.len()
        ));
    }

    // 3. medir a integridade AGORA — a janela em que o jogo ainda está suspenso.
    //
    // 🚨 A ordem aqui não é preferência, é a única que funciona. O Loader só dá
    // `ResumeThread` DEPOIS de receber o HELLO_ACK; enquanto isso a thread
    // principal do jogo está parada e não abriu arquivo nenhum. Assim que ele
    // roda, o cliente abre a `data.grf` em modo EXCLUSIVO — e qualquer leitura
    // nossa depois disso morre com `ERROR_SHARING_VIOLATION` (os error 32).
    //
    // Medido em campo antes desta mudança: `grf ok=4 ilegiveis=data.grf` — ou
    // seja, a verificação ficava cega justamente no arquivo que mais importa,
    // e em silêncio. Medir aqui atrasa o `ResumeThread` pelo tempo da leitura
    // (cabeçalho + tabela, não os GB), que a telinha do RagnaShield cobre.
    //
    // O tempo vai para o log de propósito: se um dia ficar caro numa máquina
    // lenta, o número está lá em vez de virar discussão.
    let t0 = std::time::Instant::now();
    let integridade = crate::integridade::verificar();
    let ms = t0.elapsed().as_millis();
    for l in &integridade {
        sys::log_dll(&format!("integridade: {}", l));
    }
    sys::log_dll(&format!("integridade medida em {} ms (jogo suspenso)", ms));

    // 4. responder HELLO_ACK
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
    Ok(integridade)
}

/// A cada quantos batimentos (5 s cada) pedir um ticket fresco, ate o login
/// sair. 3 batimentos = 15 s, bem dentro dos 30 s de validade.
const BATIMENTOS_POR_RENOVACAO: u32 = 3;

/// A cada quantos batimentos varrer em busca de depurador. 6 × 5 s = 30 s.
///
/// A integridade roda uma vez, no arranque, porque arquivo em disco não muda
/// sozinho. Depurador é o oposto: **anexa depois**, e justamente quando o
/// jogador já está jogando. Por isso esta varredura é periódica.
const BATIMENTOS_POR_VARREDURA: u32 = 6;

fn manter_heartbeat(
    pipe: &sys::Pipe,
    opener: &mut Opener,
    sealer: &mut Sealer,
) -> Result<(), String> {
    let mut contador: u32 = 0;
    let mut perdidos: u32 = 0;
    // Último estado visto pelas detecções. Reportamos na TRANSIÇÃO, não a cada
    // varredura: um depurador que fica anexado meia hora geraria 60 relatórios
    // idênticos, afogando o log do servidor e escondendo os eventos de verdade.
    // O que interessa é "começou agora", não "continua".
    let mut visto = crate::deteccoes::Achados::default();

    loop {
        sys::dormir_ms(INTERVALO_HEARTBEAT_MS);
        contador = contador.wrapping_add(1);

        // --- Fase 6: varredura periódica ------------------------------------
        if contador % BATIMENTOS_POR_VARREDURA == 0 {
            let agora = crate::deteccoes::procurar_depurador();
            if agora != visto {
                let linhas = crate::deteccoes::linhas_de_report(&agora);
                if linhas.is_empty() {
                    // Voltou ao normal: registra local, sem gastar um REPORT.
                    sys::log_dll("deteccoes: ambiente voltou ao normal");
                } else {
                    for l in &linhas {
                        sys::log_dll(&format!("deteccao: {}", l));
                    }
                    let payload = mensagens::montar_report(&linhas);
                    match sealer.seal(Opcode::Report, &payload) {
                        Ok(f) => {
                            if pipe.escrever(&f).is_err() {
                                return Err("Loader nao aceitou o REPORT".to_string());
                            }
                        }
                        Err(e) => sys::log_dll(&format!("cifrando REPORT de deteccao: {}", e)),
                    }
                }
                visto = agora;
            }
        }

        // --- ticket fresco, ate o login sair -------------------------------
        //
        // O ticket do HELLO vale 30 s a partir do clique em JOGAR. Se o jogador
        // demora no login, ele expira. Pedimos um novo a cada 15 s enquanto o
        // login nao saiu; depois disso nao ha mais o que proteger nesta conexao.
        if contador % BATIMENTOS_POR_RENOVACAO == 0 && !crate::netgate::login_ja_saiu() {
            let req = sealer
                .seal(Opcode::TicketReq, &[])
                .map_err(|e| format!("cifrando TICKET_REQ: {}", e))?;
            if pipe.escrever(&req).is_err() {
                return Err("Loader nao aceitou o TICKET_REQ".to_string());
            }
        }

        // --- heartbeat -----------------------------------------------------
        let payload = mensagens::montar_heartbeat(contador);
        let frame = sealer
            .seal(Opcode::Heartbeat, &payload)
            .map_err(|e| format!("cifrando HEARTBEAT: {}", e))?;
        if let Err(e) = pipe.escrever(&frame) {
            return Err(format!("Loader nao aceitou o HEARTBEAT: {}", e));
        }

        // Ler as respostas ate reconhecer o HEARTBEAT_ACK deste ciclo. Um
        // TICKET_RSP pode chegar no meio; tratamos e continuamos lendo.
        let mut viu_ack = false;
        for _ in 0..4 {
            match pipe.ler(PRAZO_ACK_MS) {
                Ok(bruto) => match opener.open(&bruto) {
                    Ok(f) if f.opcode_raw == Opcode::HeartbeatAck.as_u8() => {
                        viu_ack = true;
                        break;
                    }
                    Ok(f) if f.opcode_raw == Opcode::TicketRsp.as_u8() => {
                        if let Some(t) = mensagens::ler_ticket_rsp(&f.payload, TICKET_LEN) {
                            if crate::netgate::atualizar_ticket(t) {
                                sys::log_dll("ticket renovado");
                            }
                        } else {
                            sys::log_dll("TICKET_RSP sem ticket (Auth Service caiu?) — mantendo o anterior");
                        }
                        // Continua lendo: o HEARTBEAT_ACK ainda pode vir.
                    }
                    Ok(f) if f.opcode_raw == Opcode::ReportAck.as_u8() => {
                        // 5c-1: o servidor está em modo report, então a ação vem
                        // "report". Só registramos — a DLL não age sozinha; quem
                        // decidiria matar (5c-2) seria o Loader, pela política.
                        let acao = mensagens::ler_report_ack(&f.payload);
                        sys::log_dll(&format!("REPORT_ACK recebido, acao={}", acao));
                    }
                    Ok(f) if f.opcode_raw == Opcode::Shutdown.as_u8() => {
                        return Ok(());
                    }
                    Ok(_) => { /* opcode inesperado: ignora, como manda o protocolo */ }
                    Err(_) => break, // frame corrompido: conta como batimento perdido
                },
                Err(_) => break, // timeout
            }
        }

        if viu_ack {
            perdidos = 0;
        } else {
            perdidos += 1;
        }

        if perdidos >= BATIMENTOS_PERDIDOS_ATE_MORRER {
            return Err(format!(
                "{} batimentos sem resposta do Loader — encerrando o cliente",
                perdidos
            ));
        }
    }
}
