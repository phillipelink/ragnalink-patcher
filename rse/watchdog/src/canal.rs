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

    // O `apertar_mao` devolve o relato do arranque porque ele é medido LÁ DENTRO,
    // antes do HELLO_ACK — ver o comentário sobre a janela suspensa. Junto vem a
    // vigia de módulos, já com a linha de base tirada na mesma janela.
    let (relato_inicial, vigia, base_codigo) = apertar_mao(&pipe, &mut opener, &mut sealer)?;

    // Só o ENVIO fica aqui: o canal já está de pé e o jogo já foi retomado, então
    // reportar não atrasa ninguém. Falha ao enviar NÃO é fatal.
    enviar_report_inicial(&pipe, &mut sealer, relato_inicial);

    manter_heartbeat(&pipe, &mut opener, &mut sealer, vigia, base_codigo)
}

/// Manda o relato do arranque — integridade (5c) + inventário de módulos (6.2).
/// Best-effort: se o pipe recusar, só registra e segue.
fn enviar_report_inicial(pipe: &sys::Pipe, sealer: &mut Sealer, linhas: Vec<String>) {
    if linhas.is_empty() {
        sys::log_dll("arranque: nada a reportar");
        return;
    }
    match enviar_report(pipe, sealer, &linhas) {
        Ok(()) => sys::log_dll(&format!("REPORT enviado ({} linha(s))", linhas.len())),
        Err(e) => sys::log_dll(&format!("nao consegui enviar o REPORT do arranque: {}", e)),
    }
}

/// Quantos frames uma única varredura pode gerar.
///
/// 4 lotes ≈ 330 achados por varredura. Além disso, o `lotes_de_report`
/// substitui o excedente por uma linha `6040` dizendo quantos ficaram de fora.
/// O teto existe porque uma máquina barulhenta chegou a 95 achados por
/// varredura na Fase 6.4b — e nada garante que outra não chegue a mil.
const MAX_LOTES_POR_REPORT: usize = 4;

/// Cifra e envia um `REPORT`, quebrando em quantos frames forem necessários.
///
/// # Por que não é mais uma função só de "empacotar"
///
/// A versão anterior montava **um** payload com todas as linhas e o entregava
/// ao `seal`. Quando o total passava de `FRAME_MAX_PAYLOAD` (8192 B), o `seal`
/// recusava com `PAYLOAD_TOO_LARGE`, e todos os chamadores tratavam o erro do
/// mesmo jeito: `sys::log_dll(&e)` — registra e segue. Resultado: **o relatório
/// inteiro sumia a caminho do servidor**, sem que o servidor soubesse que algo
/// havia sumido.
///
/// Aconteceu com 95 achados (9335 B). O modo de falhar era o pior possível:
/// quanto mais grave o estado do cliente, mais linhas, mais chance de o alerta
/// não chegar. A lógica de quebra está no `mensagens.rs`, que é puro e tem
/// teste para este caso exato.
fn enviar_report(pipe: &sys::Pipe, sealer: &mut Sealer, linhas: &[String]) -> Result<(), String> {
    let lotes = mensagens::lotes_de_report(
        linhas,
        rse_protocol::version::FRAME_MAX_PAYLOAD,
        MAX_LOTES_POR_REPORT,
    );
    if lotes.len() > 1 {
        sys::log_dll(&format!(
            "REPORT: {} linha(s) nao cabem num frame; enviando em {} lotes",
            linhas.len(),
            lotes.len()
        ));
    }
    for lote in &lotes {
        let frame = sealer
            .seal(Opcode::Report, lote)
            .map_err(|e| format!("cifrando REPORT: {}", e))?;
        if pipe.escrever(&frame).is_err() {
            return Err("Loader nao aceitou o REPORT".to_string());
        }
    }
    Ok(())
}

/// O que o aperto de mão mediu na janela em que o jogo estava suspenso.
type RelatoDoArranque = (
    Vec<String>,
    Option<crate::modulos::Vigia>,
    Vec<crate::codigo::Marca>,
);

fn apertar_mao(
    pipe: &sys::Pipe,
    opener: &mut Opener,
    sealer: &mut Sealer,
) -> Result<RelatoDoArranque, String> {

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

    // 3b. linha de base dos módulos (6.2) — a MESMA janela suspensa, e pelo mesmo
    // tipo de razão que a integridade.
    //
    // Aqui a lista de módulos é só o que o `.exe` importa estaticamente mais a
    // nossa DLL: o jogo ainda não executou uma instrução sequer, então não
    // carregou D3D, codec, IME nem overlay nenhum. É a foto mais limpa que este
    // processo vai ter. Tudo que aparecer depois é carregamento em tempo de
    // execução — e é sobre esse "depois" que a varredura periódica fala.
    //
    // Falhar aqui NÃO derruba nada: sem linha de base a varredura fica desligada
    // nesta sessão e o motivo vai para o log. Um erro de API não pode virar
    // acusação nem impedir o jogador de jogar.
    let mut relato = integridade;
    let t1 = std::time::Instant::now();
    let vigia = match crate::modulos::iniciar_vigia() {
        Ok((v, inventario)) => {
            for l in &inventario {
                sys::log_dll(&format!("modulos: {}", l));
            }
            sys::log_dll(&format!(
                "modulos: linha de base tirada em {} ms",
                t1.elapsed().as_millis()
            ));
            relato.extend(inventario);
            Some(v)
        }
        Err(e) => {
            sys::log_dll(&format!(
                "modulos: sem linha de base ({}) — varredura de modulos DESLIGADA nesta sessao",
                e
            ));
            None
        }
    };

    // 4. responder HELLO_ACK
    let payload = mensagens::montar_hello_ack(
        RSE_PROTOCOL,
        sys::pid_atual(),
        sys::tid_atual(),
        sys::base_do_modulo(),
    );
    // 6.5 — a foto do código, tirada AQUI e não antes.
    //
    // 🚨 Depois do netgate (passo 2), de propósito: nós mesmos instalamos hooks
    // inline em `send` e `WSASend`, e uma foto anterior a isso faria o RSE
    // acusar a si mesmo em toda sessão. O operador aprenderia a ignorar
    // justamente o código que significa "alguém remendou o jogo".
    //
    // E ainda antes do HELLO_ACK, com a thread principal suspensa: ninguém de
    // fora teve tempo de escrever nada. É a mesma janela privilegiada que a
    // integridade usa para conseguir ler a `data.grf`.
    let mut relato = relato;
    let base_codigo = crate::codigo::fotografar();
    if base_codigo.is_empty() {
        sys::log_dll("codigo: nao consegui fotografar nada; vigilancia 6.5 desligada");
    } else {
        crate::codigo::registrar_base(&base_codigo);
        relato.push(crate::codigo::linha_da_base(&base_codigo));
    }

    let frame = sealer
        .seal(Opcode::HelloAck, &payload)
        .map_err(|e| format!("cifrando HELLO_ACK: {}", e))?;
    pipe.escrever(&frame)
        .map_err(|e| format!("enviando HELLO_ACK: {}", e))?;
    Ok((relato, vigia, base_codigo))
}

/// A cada quantos batimentos (5 s cada) pedir um ticket fresco, ate o login
/// sair. 3 batimentos = 15 s, bem dentro dos 30 s de validade.
const BATIMENTOS_POR_RENOVACAO: u32 = 3;

/// A cada quantos batimentos rodar as varreduras da Fase 6. 6 × 5 s = 30 s.
///
/// A integridade roda uma vez, no arranque, porque arquivo em disco não muda
/// sozinho. Depurador (6.1) e módulo injetado (6.2) são o oposto: **chegam
/// depois**, e justamente quando o jogador já está jogando. Por isso estas
/// varreduras são periódicas — e as duas cabem no mesmo tique, porque as duas são
/// baratas (consulta de API e uma foto do Toolhelp, sem I/O de disco pesado).
const BATIMENTOS_POR_VARREDURA: u32 = 6;

/// A cada quantos batimentos rodar a varredura **cara**. 12 × 5 s = 60 s.
///
/// A 6.4b (`handles.rs`) não é como as outras: ela pede ao kernel a tabela de
/// **todos os handles de todos os processos**, que numa máquina comum são
/// dezenas de milhares de entradas e alguns megabytes de resposta. Rodar isso a
/// cada 30 s, dentro do processo do jogo, seria pagar caro por informação que
/// quase nunca muda — quem anexa um editor de memória fica anexado.
///
/// 60 s é o compromisso: um minuto é curtíssimo na escala de quem está trapaceando,
/// e metade do custo. O buffer também é reaproveitado entre varreduras (ver
/// `Sentinela`), então o preço recorrente é a chamada, não a alocação.
const BATIMENTOS_POR_VARREDURA_CARA: u32 = 12;

fn manter_heartbeat(
    pipe: &sys::Pipe,
    opener: &mut Opener,
    sealer: &mut Sealer,
    mut vigia: Option<crate::modulos::Vigia>,
    base_codigo: Vec<crate::codigo::Marca>,
) -> Result<(), String> {
    let mut contador: u32 = 0;
    let mut perdidos: u32 = 0;
    // Último estado visto pelas detecções. Reportamos na TRANSIÇÃO, não a cada
    // varredura: um depurador que fica anexado meia hora geraria 60 relatórios
    // idênticos, afogando o log do servidor e escondendo os eventos de verdade.
    // O que interessa é "começou agora", não "continua".
    let mut visto = crate::deteccoes::Achados::default();
    // 6.4 — processos proibidos. Igual à lógica do depurador: só reportamos
    // a TRANSIÇÃO (processo novo que ainda não foi reportado). Quando o usuário
    // fecha o Cheat Engine já logado, registramos localmente, sem gastar um
    // REPORT — o que importa é que ele estava aberto, não que fechou.
    let mut processos_vistos = std::collections::BTreeSet::<String>::new();
    // 6.3 — relógio. A base é tirada AQUI, no arranque: as duas fontes de tempo
    // precisam de um ponto de partida comum para a razão significar alguma coisa.
    let mut relogio = crate::relogio::Relogio::novo();
    if relogio.is_none() {
        sys::log_dll("relogio: sem QPC nesta maquina; deteccao 6.3 desligada nesta sessao");
    }

    // 6.4b — quem segura handle com escrita sobre nós. Estado próprio porque a
    // varredura reaproveita o buffer e guarda quem já reportou.
    let mut sentinela = crate::handles::Sentinela::nova();

    // 🚨 A linha de base sai AGORA, não daqui a 60 s.
    //
    // A primeira versão tirava a foto na primeira varredura periódica — ou seja,
    // um minuto depois de o jogo abrir. Isso abria um buraco de 60 segundos:
    // **um editor de memória anexado nesse intervalo entrava na base**, e a
    // partir daí era classificado como "esperado" para o resto da sessão.
    //
    // Não é teoria — aconteceu no primeiro teste. O `rse-testhandle` foi
    // iniciado antes do minuto, entrou na base, e passou a sair como `6030`
    // informativo em vez de `3003`. Um cheater que abrisse o CE junto com o jogo
    // teria exatamente o mesmo tratamento.
    //
    // Aqui estamos logo depois do aperto de mão: o jogo acabou de ser retomado e
    // ninguém teve tempo de anexar nada. É o momento mais limpo que existe, o
    // mesmo raciocínio do inventário de módulos da 6.2.
    match crate::handles::varrer(&mut sentinela) {
        Ok(linhas) if !linhas.is_empty() => {
            for l in &linhas {
                sys::log_dll(&format!("handles: {}", l));
            }
            enviar_report(pipe, sealer, &linhas)?;
        }
        Ok(_) => {}
        Err(e) => sys::log_dll(&format!("handles: base falhou ({})", e)),
    }

    loop {
        sys::dormir_ms(INTERVALO_HEARTBEAT_MS);
        contador = contador.wrapping_add(1);

        // --- Fase 6: varreduras periódicas ----------------------------------
        if contador % BATIMENTOS_POR_VARREDURA == 0 {
            // 6.1 — depurador. Relata na TRANSIÇÃO (ver `visto`).
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
                    enviar_report(pipe, sealer, &linhas)?;
                }
                visto = agora;
            }

            // 6.2 — módulos novos desde o arranque.
            //
            // A "transição" aqui é o próprio contrato da `Vigia`: ela só devolve
            // o que ainda não tinha visto, e guarda o que devolveu. Um overlay
            // que fica carregado a tarde inteira gera UMA linha, não uma a cada
            // 30 s. Sem isso o canal viraria ruído e o operador aprenderia a
            // ignorá-lo — que é o mesmo que não ter detecção.
            if let Some(v) = vigia.as_mut() {
                match crate::modulos::varrer(v) {
                    Ok(linhas) if !linhas.is_empty() => {
                        for l in &linhas {
                            sys::log_dll(&format!("modulos: {}", l));
                        }
                        enviar_report(pipe, sealer, &linhas)?;
                    }
                    Ok(_) => {}
                    // Falha de API não acusa ninguém e não derruba a sessão:
                    // registra e tenta de novo no próximo tique.
                    Err(e) => sys::log_dll(&format!("modulos: varredura falhou ({})", e)),
                }
            }

            // 6.3 — relógio adulterado (speedhack).
            //
            // Cabe na varredura barata: são duas leituras e uma divisão. A parte
            // cara desta detecção é o TEMPO que precisa passar, não o cálculo.
            if let Some(r) = relogio.as_mut() {
                let linhas = crate::relogio::verificar(r);
                if !linhas.is_empty() {
                    for l in &linhas {
                        sys::log_dll(&format!("relogio: {}", l));
                    }
                    enviar_report(pipe, sealer, &linhas)?;
                }
            }

            // 6.4 — processos proibidos.
            //
            // A varredura de processos é mais cara que IsDebuggerPresent mas
            // ainda assim barata: um snapshot de ~200 processos leva <1 ms na
            // maioria das máquinas, e a fazemos só a cada BATIMENTOS_POR_VARREDURA
            // (30 s), então o custo total é insignificante.
            //
            // Lógica de transição:
            //   novos = agora − vistos   → reportar (o processo acabou de aparecer)
            //   sumidos = vistos − agora → só logar localmente (ele fechou)
            //   vistos ← agora           → atualizar estado
            match crate::processos::procurar_proibidos() {
                None => {
                    // Falha de API (sem permissão para snapshot, por exemplo).
                    // Não acusamos ninguém e não quebramos a sessão.
                    sys::log_dll("processos: nao foi possivel criar snapshot");
                }
                Some(achados) => {
                    // Processos que apareceram desde a última varredura.
                    let novos: std::collections::BTreeSet<String> = achados
                        .processos
                        .difference(&processos_vistos)
                        .cloned()
                        .collect();

                    // Processos que sumiram desde a última varredura.
                    let sumidos: std::collections::BTreeSet<String> = processos_vistos
                        .difference(&achados.processos)
                        .cloned()
                        .collect();

                    if !sumidos.is_empty() {
                        for nome in &sumidos {
                            sys::log_dll(&format!("processos: {} encerrado", nome));
                        }
                    }

                    if !novos.is_empty() {
                        let linhas = crate::processos::linhas_de_report(&novos);
                        for l in &linhas {
                            sys::log_dll(&format!("processos: {}", l));
                        }
                        enviar_report(pipe, sealer, &linhas)?;
                    }

                    processos_vistos = achados.processos;
                }
            }
        }

        // --- Fase 6.4b: a varredura cara, em cadência própria ----------------
        //
        // Fora do `if` acima de propósito: 12 não é múltiplo de 6 por acidente —
        // é para que a varredura cara caia SEMPRE junto com uma barata, e não
        // sozinha num tique intermediário. Assim o custo se concentra em um
        // batimento a cada dois, em vez de espalhar picos por todos eles.
        if contador % BATIMENTOS_POR_VARREDURA_CARA == 0 {
            // 6.5 — o código ainda é o que era?
            //
            // Cabe aqui e não na varredura barata porque re-hashear a seção de
            // código do jogo custa alguns megabytes de leitura. Fica junto da
            // 6.4b de propósito: as duas respondem a mesma pergunta por ângulos
            // opostos — quem PODE escrever, e o que FOI escrito.
            if !base_codigo.is_empty() {
                let agora = crate::codigo::fotografar();
                let linhas = crate::codigo::comparar(&base_codigo, &agora);
                if !linhas.is_empty() {
                    for l in &linhas {
                        sys::log_dll(&format!("codigo: {}", l));
                    }
                    enviar_report(pipe, sealer, &linhas)?;
                }
            }

            match crate::handles::varrer(&mut sentinela) {
                Ok(linhas) if !linhas.is_empty() => {
                    for l in &linhas {
                        sys::log_dll(&format!("handles: {}", l));
                    }
                    enviar_report(pipe, sealer, &linhas)?;
                }
                Ok(_) => {}
                // Falha de API não acusa ninguém e não derruba a sessão.
                Err(e) => sys::log_dll(&format!("handles: varredura falhou ({})", e)),
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
