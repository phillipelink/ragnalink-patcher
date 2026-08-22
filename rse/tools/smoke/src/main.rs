//! `rse-smoke` — prova o circuito do servidor de ponta a ponta, sem Loader nem DLL.
//!
//! ```text
//! rse-smoke --auth http://127.0.0.1:8081 --login 127.0.0.1:6900 --user teste --pass 123456
//! ```
//!
//! # Por que isto existe
//!
//! O RSE so protege de verdade quando o launcher, o Loader, a DLL, o Auth
//! Service e o login-server estao todos de pe. Isso e a Fase 5. Mas as duas
//! metades do SERVIDOR ja existem hoje, e esperar ate la para descobrir que
//! elas nao conversam seria caro.
//!
//! Esta ferramenta finge ser o cliente: pede um ticket a API, abre TCP no
//! login-server, manda o `0x0AAA` seguido do packet de login normal, e conta o
//! que aconteceu. Se isto funcionar, o unico pedaco que falta e o Windows.
//!
//! # O que ela NAO e
//!
//! Nao e um cliente de Ragnarok, nao entra no jogo, nao serve para jogar. Ela
//! para no primeiro packet de resposta do login-server. Tambem nao fala TLS: os
//! caminhos que ela usa sao os internos do servidor (a porta do container e a
//! porta do login), onde nao ha TLS mesmo. Rode-a NO servidor.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rse_protocol::crypto::to_hex;
use rse_protocol::ticket::{parse_login_packet, RseTicket};
use rse_protocol::version::*;

// ===========================================================================
//  Argumentos
// ===========================================================================

struct Args {
    auth: String,
    login: String,
    user: String,
    pass: String,
    versao_cliente: u32,
    clienttype: u8,
    sem_ticket: bool,
}

fn uso() -> ! {
    eprintln!(
        "rse-smoke — prova o circuito do RagnaShield Engine no servidor\n\
         \n\
         USO:\n  \
           rse-smoke --auth <URL> --login <HOST:PORTA> --user <CONTA> --pass <SENHA> [opcoes]\n\
         \n\
         OBRIGATORIOS:\n  \
           --auth   <URL>        RSE Auth Service, em HTTP simples.\n                         \
                                 No servidor: http://127.0.0.1:8081\n  \
           --login  <HOST:PORTA> login-server do rAthena. Normalmente 127.0.0.1:6900\n  \
           --user   <CONTA>      conta de teste que EXISTE no banco\n  \
           --pass   <SENHA>      senha dela\n\
         \n\
         OPCOES:\n  \
           --sem-ticket          pula o 0x0AAA e manda so o login.\n                         \
                                 E assim que se confirma que o rse_enforce: on\n                         \
                                 esta mesmo barrando quem nao apresenta ticket.\n  \
           --versao <N>          campo `version` do packet de login (padrao 55)\n  \
           --clienttype <N>      campo `clienttype` (padrao 0)\n"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut a = Args {
        auth: String::new(),
        login: String::new(),
        user: String::new(),
        pass: String::new(),
        versao_cliente: 55,
        clienttype: 0,
        sem_ticket: false,
    };

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut valor = || it.next().unwrap_or_else(|| uso());
        match arg.as_str() {
            "--auth" => a.auth = valor(),
            "--login" => a.login = valor(),
            "--user" => a.user = valor(),
            "--pass" => a.pass = valor(),
            "--versao" => a.versao_cliente = valor().parse().unwrap_or(55),
            "--clienttype" => a.clienttype = valor().parse().unwrap_or(0),
            "--sem-ticket" => a.sem_ticket = true,
            "-h" | "--help" => uso(),
            outro => {
                eprintln!("argumento desconhecido: {}\n", outro);
                uso()
            }
        }
    }

    if a.auth.is_empty() || a.login.is_empty() || a.user.is_empty() || a.pass.is_empty() {
        uso()
    }
    a
}

// ===========================================================================
//  HTTP minimo
// ===========================================================================
//
//  Escrito a mao, sem biblioteca, e e uma escolha: esta ferramenta compartilha
//  a regra do `rse-protocol` de nao arrastar dependencia. Um cliente HTTP
//  completo traria dezenas de crates para fazer dois POST contra um endereco
//  local que responde JSON de tres campos.
//
//  Limitacoes assumidas: HTTP/1.1 simples, sem TLS, sem redirecionamento, sem
//  chunked. E o suficiente para falar com o container ao lado.
//
//  Sobre o `X-Forwarded-Proto: https` que vai em todo pedido:
//
//  O Portal roda atras do nginx, que termina o TLS e repassa em HTTP puro para
//  o Kestrel na 8081. O `Startup` liga `app.UseHttpsRedirection()`, entao o
//  ASP.NET so considera o pedido seguro se o proxy disser que era HTTPS na
//  ponta — e e esse header que diz. Como esta ferramenta bate direto na 8081,
//  pulando o nginx, sem o header ela leva um `307 Temporary Redirect` para
//  `https://<host>/...` (repare: sem a porta, ou seja, para a 443), e o corpo
//  volta vazio. O header reproduz o que o nginx faria.
//
//  Nao e uma gambiarra de teste: e exatamente o mesmo header que o proxy real
//  poe. O Loader da Fase 4 vai falar HTTPS pelo nome publico e nao precisa
//  disto.

/// Header que finge ser o nginx. Ver o comentario do bloco acima.
const CABECALHO_PROXY: &str = "X-Forwarded-Proto: https";

fn http_post(url: &str, caminho: &str, corpo: &str) -> Result<String, String> {
    let (host_porta, host_cabecalho) = destino(url)?;

    let mut fluxo = TcpStream::connect(&host_porta)
        .map_err(|e| format!("nao conectou em {}: {}", host_porta, e))?;
    fluxo
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    let pedido = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n{}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        caminho,
        host_cabecalho,
        CABECALHO_PROXY,
        corpo.len(),
        corpo
    );
    fluxo.write_all(pedido.as_bytes()).map_err(|e| e.to_string())?;

    let mut bruto = Vec::new();
    fluxo.read_to_end(&mut bruto).map_err(|e| e.to_string())?;
    let texto = String::from_utf8_lossy(&bruto).to_string();

    conferir_resposta(&texto)
}

fn http_get(url: &str, caminho: &str) -> Result<String, String> {
    let (host_porta, host_cabecalho) = destino(url)?;
    let mut fluxo = TcpStream::connect(&host_porta)
        .map_err(|e| format!("nao conectou em {}: {}", host_porta, e))?;
    fluxo
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    let pedido = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n{}\r\nConnection: close\r\n\r\n",
        caminho, host_cabecalho, CABECALHO_PROXY
    );
    fluxo.write_all(pedido.as_bytes()).map_err(|e| e.to_string())?;

    let mut bruto = Vec::new();
    fluxo.read_to_end(&mut bruto).map_err(|e| e.to_string())?;
    let texto = String::from_utf8_lossy(&bruto).to_string();

    conferir_resposta(&texto)
}

/// Separa cabecalho de corpo e reprova qualquer status fora do 2xx.
///
/// O caso do 3xx ganha mensagem propria porque o corpo vem vazio: sem isso o
/// erro seria `HTTP 307 — ` e ninguem descobriria o motivo. Mostrar o
/// `Location` entrega o diagnostico pronto.
fn conferir_resposta(texto: &str) -> Result<String, String> {
    let (cabecalho, corpo) = texto
        .split_once("\r\n\r\n")
        .ok_or_else(|| "resposta HTTP sem corpo".to_string())?;

    let status: u16 = cabecalho
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if (300..400).contains(&status) {
        let destino = cabecalho
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("location:"))
            .map(|l| l[9..].trim())
            .unwrap_or("(sem Location)");
        return Err(format!(
            "HTTP {} — o servidor redirecionou para {}.\n         \
             Isto costuma ser o `UseHttpsRedirection` do ASP.NET: o pedido \
             chegou como HTTP puro\n         e a aplicacao so aceita HTTPS. \
             Confira se a --auth aponta para a porta interna certa.",
            status, destino
        ));
    }

    if !(200..300).contains(&status) {
        return Err(format!("HTTP {} — {}", status, corpo.trim()));
    }
    Ok(corpo.to_string())
}

fn destino(url: &str) -> Result<(String, String), String> {
    let sem_esquema = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("--auth precisa comecar com http:// (sem TLS): {}", url))?;
    let host = sem_esquema.trim_end_matches('/').to_string();
    let host_porta = if host.contains(':') {
        host.clone()
    } else {
        format!("{}:80", host)
    };
    Ok((host_porta, host))
}

/// Extrai um campo de texto do JSON.
///
/// NAO e um parser de JSON: procura `"chave":"` e le ate a proxima aspa. Basta
/// para as respostas do Auth Service, que sao planas e nossas. Se um dia
/// precisar de mais que isso, e sinal de que a ferramenta cresceu demais.
fn campo(json: &str, chave: &str) -> Option<String> {
    let alvo = format!("\"{}\"", chave);
    let i = json.find(&alvo)? + alvo.len();
    let resto = &json[i..];
    let j = resto.find(':')? + 1;
    let resto = resto[j..].trim_start();
    if let Some(sem_aspas) = resto.strip_prefix('"') {
        let fim = sem_aspas.find('"')?;
        Some(sem_aspas[..fim].to_string())
    } else {
        let fim = resto.find([',', '}']).unwrap_or(resto.len());
        Some(resto[..fim].trim().to_string())
    }
}

/// Base64 padrao -> bytes. Tambem escrito a mao, pelo mesmo motivo.
fn de_base64(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut valor = [255u8; 256];
    for (i, c) in T.iter().enumerate() {
        valor[*c as usize] = i as u8;
    }

    let mut saida = Vec::new();
    let mut acumulador: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = valor[c as usize];
        if v == 255 {
            return None;
        }
        acumulador = (acumulador << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            saida.push((acumulador >> bits) as u8);
        }
    }
    Some(saida)
}

// ===========================================================================
//  Packet de login do Ragnarok
// ===========================================================================

/// Monta o `CA_LOGIN` (0x0064), 55 bytes.
///
/// `<header>.W <version>.L <username>.24B <password>.24B <clienttype>.B`
///
/// Tudo little-endian, e os textos preenchidos com zero ate o tamanho fixo -
/// que e como o cliente de verdade manda.
fn monta_login(versao: u32, usuario: &str, senha: &str, clienttype: u8) -> Vec<u8> {
    let mut p = vec![0u8; 55];
    p[0..2].copy_from_slice(&0x0064u16.to_le_bytes());
    p[2..6].copy_from_slice(&versao.to_le_bytes());

    let u = usuario.as_bytes();
    let s = senha.as_bytes();
    p[6..6 + u.len().min(23)].copy_from_slice(&u[..u.len().min(23)]);
    p[30..30 + s.len().min(23)].copy_from_slice(&s[..s.len().min(23)]);
    p[54] = clienttype;
    p
}

fn explica_recusa(codigo: u8) -> &'static str {
    match codigo {
        0 => "conta nao existe",
        1 => "senha incorreta",
        2 => "conta expirada",
        3 => "recusado pelo servidor  <-- e este que o RSE usa",
        4 => "servidor cheio",
        5 => "versao de cliente incompativel",
        6 => "banido temporariamente",
        _ => "outro motivo",
    }
}

// ===========================================================================

fn main() {
    let a = parse_args();
    let mut falhas = 0;

    println!("rse-smoke — RSE_PROTOCOL {}\n", RSE_PROTOCOL);

    // --- 1. politica ------------------------------------------------------
    println!("1. GET {}/rse/v1/policy", a.auth);
    match http_get(&a.auth, "/rse/v1/policy") {
        Ok(j) => {
            let enforce = campo(&j, "enforce").unwrap_or_else(|| "?".into());
            println!("   ok    enforce={}  epoch={}", enforce,
                     campo(&j, "policy_epoch").unwrap_or_else(|| "?".into()));
            if enforce == "off" {
                println!("   nota  o Auth Service esta em 'off'. Isso e so o que ele");
                println!("         RECOMENDA ao cliente; quem decide barrar e o");
                println!("         rse_enforce do login_athena.conf.");
            }
        }
        Err(e) => {
            println!("   FALHA {}", e);
            falhas += 1;
        }
    }

    // --- 2. sessao --------------------------------------------------------
    // Numa instalacao de verdade estes dois hashes vem do launcher: o SHA-256
    // do proprio executavel e o hash dos identificadores da maquina. Aqui sao
    // fixos de proposito, para o teste ser reproduzivel.
    let build = "0".repeat(64);
    let hint = "11".repeat(32);

    println!("\n2. POST {}/rse/v1/session", a.auth);
    let corpo = format!(
        r#"{{"protocol":{},"launcherBuild":"{}","machineHint":"{}","lastPatchIndex":0,"osVersion":"rse-smoke"}}"#,
        RSE_PROTOCOL, build, hint
    );

    let credencial = match http_post(&a.auth, "/rse/v1/session", &corpo) {
        Ok(j) => {
            let id = campo(&j, "session_id").unwrap_or_default();
            println!("   ok    session_id={}  expira em {}s", id,
                     campo(&j, "expires_in").unwrap_or_else(|| "?".into()));
            campo(&j, "session_credential")
        }
        Err(e) => {
            println!("   FALHA {}", e);
            println!("         O RSE esta habilitado no site? Confira");
            println!("         RseSettings__Habilitado=true no .env.");
            falhas += 1;
            None
        }
    };

    // --- 3. ticket --------------------------------------------------------
    let mut ticket: Option<Vec<u8>> = None;

    if let Some(cred) = &credencial {
        println!("\n3. POST {}/rse/v1/ticket", a.auth);
        let corpo = format!(
            r#"{{"protocol":{},"sessionCredential":"{}","clientHash":"{}"}}"#,
            RSE_PROTOCOL, cred, hint
        );
        match http_post(&a.auth, "/rse/v1/ticket", &corpo) {
            Ok(j) => match campo(&j, "ticket").and_then(|b| de_base64(&b)) {
                Some(bytes) if bytes.len() == TICKET_LEN => {
                    println!("   ok    ticket de {} bytes, key_id={}", bytes.len(),
                             campo(&j, "key_id").unwrap_or_else(|| "?".into()));

                    // Leitura local so para conferir que o formato bate. Quem
                    // valida de verdade e o login-server - nao temos (nem
                    // queremos ter) a K_ticket aqui.
                    if let Ok(t) = RseTicket::parse_unverified(&bytes) {
                        println!("         versao={} flags=0x{:02x} ttl={}ms", t.version, t.flags.0, t.ttl_ms);
                        println!("         nonce={}", to_hex(&t.nonce));
                        println!("         machine_fp={}...", &to_hex(&t.machine_fp)[..16]);
                    }
                    ticket = Some(bytes);
                }
                Some(bytes) => {
                    println!("   FALHA ticket com {} bytes, esperado {}", bytes.len(), TICKET_LEN);
                    falhas += 1;
                }
                None => {
                    println!("   FALHA resposta sem ticket utilizavel: {}", j.trim());
                    falhas += 1;
                }
            },
            Err(e) => {
                println!("   FALHA {}", e);
                falhas += 1;
            }
        }
    }

    // --- 4. login-server --------------------------------------------------
    println!("\n4. TCP {}", a.login);
    match TcpStream::connect(&a.login) {
        Err(e) => {
            println!("   FALHA nao conectou: {}", e);
            falhas += 1;
        }
        Ok(mut fluxo) => {
            let _ = fluxo.set_read_timeout(Some(Duration::from_secs(10)));
            println!("   ok    conectado");

            if a.sem_ticket {
                println!("   nota  --sem-ticket: pulando o 0x0AAA de proposito");
            } else if let Some(t) = &ticket {
                let mut fixo = [0u8; TICKET_LEN];
                fixo.copy_from_slice(t);
                let pkt = rse_protocol::ticket::encode_login_packet(&fixo);

                // Confere localmente que o packet fecha, antes de mandar.
                match parse_login_packet(&pkt) {
                    Ok(_) => println!("   ok    packet 0x0AAA montado ({} bytes)", pkt.len()),
                    Err(e) => {
                        println!("   FALHA packet 0x0AAA invalido: {}", e);
                        falhas += 1;
                    }
                }

                if let Err(e) = fluxo.write_all(&pkt) {
                    println!("   FALHA nao enviou o 0x0AAA: {}", e);
                    falhas += 1;
                } else {
                    println!("   ok    0x0AAA enviado");
                }
            } else {
                println!("   nota  sem ticket para enviar (etapa 3 falhou)");
            }

            let login = monta_login(a.versao_cliente, &a.user, &a.pass, a.clienttype);
            if let Err(e) = fluxo.write_all(&login) {
                println!("   FALHA nao enviou o login: {}", e);
                falhas += 1;
            } else {
                println!("   ok    0x0064 enviado ({} bytes, conta '{}')", login.len(), a.user);
            }

            // --- 5. resposta ---------------------------------------------
            println!("\n5. resposta do login-server");
            let mut buf = [0u8; 512];
            match fluxo.read(&mut buf) {
                Ok(0) => {
                    println!("   FALHA o servidor fechou a conexao sem responder.");
                    println!("         Costuma ser packet malformado - veja o console do login.");
                    falhas += 1;
                }
                Ok(n) if n >= 2 => {
                    let id = u16::from_le_bytes([buf[0], buf[1]]);
                    match id {
                        // Os dois sao AC_ACCEPT_LOGIN; qual chega depende da
                        // PACKETVER do emulador. O rAthena troca em 20170621:
                        // antes disso 0x0069, dali em diante 0x0AC4 (o mesmo
                        // packet, com o token de autenticacao web a mais).
                        // Reconhecer so um dos dois faz um login ACEITO passar
                        // por "packet inesperado" - ja aconteceu.
                        0x0069 | 0x0AC4 => {
                            let nome = if id == 0x0AC4 { "0x0AC4" } else { "0x0069" };
                            println!("   ok    {} AC_ACCEPT_LOGIN — LOGIN ACEITO ({} bytes)", nome, n);

                            // O account_id fica no offset 8 nas duas versoes.
                            // Serve para casar esta saida com a linha
                            // "Authentication accepted (account: X, id: N)"
                            // do console do login-server.
                            if n >= 12 {
                                let aid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
                                println!("         account_id={}", aid);
                            }

                            if !a.sem_ticket && ticket.is_some() {
                                println!("\n   ==> O circuito do servidor esta fechado: o Auth Service");
                                println!("       emitiu, o login-server aceitou. Falta o Windows.");
                                println!("\n   ATENCAO: em rse_enforce: log isto NAO prova que o ticket");
                                println!("   foi validado - o modo 'log' aceita mesmo com ticket ruim.");
                                println!("   A prova esta no console do login-server:");
                                println!("     sem nenhuma linha 'RSE:'  -> o ticket passou");
                                println!("     com 'RSE: ... entrou SEM ticket valido' -> foi recusado");
                            }
                        }
                        0x006a => {
                            let motivo = if n >= 3 { buf[2] } else { 255 };
                            println!("   ---   0x006A AC_REFUSE_LOGIN — recusado, motivo {} ({})",
                                     motivo, explica_recusa(motivo));
                            if motivo == 3 {
                                if a.sem_ticket {
                                    println!("\n   ==> Era o esperado com --sem-ticket e rse_enforce: on.");
                                    println!("       O login-server esta barrando quem nao apresenta ticket.");
                                } else {
                                    println!("\n   Com ticket, o motivo 3 costuma ser o RSE recusando.");
                                    println!("   Procure no console do login: \"RSE: ticket recusado\".");
                                    falhas += 1;
                                }
                            } else if motivo == 0 || motivo == 1 {
                                println!("\n   Conta ou senha erradas — isso e o login normal, nao o RSE.");
                                println!("   Use uma conta que exista para testar o RSE de verdade.");
                            }
                        }
                        // Conta como falha: um packet que esta ferramenta nao
                        // sabe ler e um resultado DESCONHECIDO, e "nenhuma
                        // falha" no rodape para um resultado desconhecido e
                        // pior do que um erro - da confianca que nao existe.
                        outro => {
                            println!("   FALHA packet 0x{:04X} nao reconhecido ({} bytes)", outro, n);
                            println!("         Nao da para dizer se o login passou. Confira o console");
                            println!("         do login-server e, se for um accept de outra PACKETVER,");
                            println!("         acrescente o id no match acima.");
                            falhas += 1;
                        }
                    }
                }
                Ok(n) => {
                    println!("   FALHA resposta curta demais ({} bytes)", n);
                    falhas += 1;
                }
                Err(e) => {
                    println!("   FALHA sem resposta: {}", e);
                    falhas += 1;
                }
            }
        }
    }

    println!("\n{}", "-".repeat(56));
    if falhas == 0 {
        println!("  Nenhuma falha.");
    } else {
        println!("  {} etapa(s) com falha.", falhas);
    }
    println!("{}", "-".repeat(56));

    std::process::exit(if falhas == 0 { 0 } else { 1 });
}
