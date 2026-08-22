//! Netgate — antepõe o packet `0x0AAA` (o ticket) na conexão de login.
//!
//! # O que ele faz, em uma frase
//!
//! Intercepta o envio de rede do Ragexe e, quando vê o packet de login saindo,
//! manda o `0x0AAA` **antes** dele, na mesma conexão. O login-server, que já sabe
//! conferir o ticket (Fase 3a), passa a recebê-lo de um cliente de verdade. É
//! esta peça que faz `rse_enforce: on` significar alguma coisa: sem ela, abrir o
//! Ragexe direto ainda conectava.
//!
//! # `send` E `WSASend`, e por quê
//!
//! O cliente do RagnaLinK não usa `send` para o login — usa `WSASend`, o envio
//! assíncrono do Winsock. Descobrimos isso do jeito certo: o hook de `send`
//! instalou, mas nunca disparou, e o log da DLL mostrou. Então enganchamos os
//! **dois**. Qualquer um que carregue o packet de login serve; o `0x0AAA` vai na
//! frente por onde o login for.
//!
//! # Por que hook de IAT, e não inline
//!
//! A *Import Address Table* do Ragexe tem um slot com o endereço de cada função
//! importada. Trocamos o valor do slot pelo nosso — um ponteiro de dados, não uma
//! instrução reescrita. É reversível e não corrompe código. O cliente importa o
//! Winsock por **ordinal** (send=19, WSASend=26), não por nome, o que também só
//! ficou claro pelo log.
//!
//! # A regra de ouro
//!
//! O `0x0AAA` vai **uma vez por conexão**, antes do primeiro packet de login
//! daquela conexão. Pré-login (hash check) passa intacto. O socket entra num
//! conjunto de "já carimbados" — para não reenviar, e para o próprio `0x0AAA` que
//! mandamos não disparar o hook em laço.

#![cfg(windows)]

use std::os::raw::{c_char, c_int};
use std::sync::Mutex;

use rse_protocol::packets;
use rse_protocol::ticket::encode_login_packet;
use rse_protocol::version::{LOGIN_PACKET_LEN, TICKET_LEN};

use crate::sys;

/// Ordinais do ws2_32.dll (estáveis, documentados).
const ORDINAL_SEND: u16 = 19;
const ORDINAL_WSASEND: u16 = 26;

/// `int WSAAPI send(SOCKET, const char*, int, int)`.
type SendFn = unsafe extern "system" fn(usize, *const c_char, c_int, c_int) -> c_int;

/// `int WSAAPI WSASend(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE)`.
type WsaSendFn = unsafe extern "system" fn(
    usize,
    *const WsaBuf,
    u32,
    *mut u32,
    u32,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
) -> c_int;

/// `WSABUF` em 32 bits: `u_long len; char* buf`. Definido a mão para não caçar
/// features do winapi; o layout é este e é estável.
#[repr(C)]
struct WsaBuf {
    len: u32,
    buf: *mut c_char,
}

struct Estado {
    /// O packet `0x0AAA` já montado (152 bytes).
    pacote_0aaa: [u8; LOGIN_PACKET_LEN],
    /// Os envios verdadeiros, salvos antes de trocar os slots. `None` se aquela
    /// função não estava importada.
    send_real: Option<SendFn>,
    wsasend_real: Option<WsaSendFn>,
    /// Sockets em que já antepusemos o ticket.
    carimbados: Vec<usize>,
    /// Quantas linhas de diagnóstico ainda vamos gravar (teto, para não encher o
    /// disco do jogador com o tráfego inteiro da partida).
    orcamento_log: u32,
}

// SAFETY: ponteiros de função são válidos em todo o processo; o acesso é
// serializado pelo Mutex.
unsafe impl Send for Estado {}

/// `Mutex::new` é `const` desde 1.63 — dá para o estado morar num `static` sem
/// `OnceLock` (que só veio na 1.70, acima da toolchain travada).
static ESTADO: Mutex<Option<Estado>> = Mutex::new(None);

/// Instala o netgate. Chamada pela `canal` logo após o HELLO (com o ticket),
/// enquanto o jogo ainda está suspenso.
pub fn instalar(ticket: &[u8]) -> Result<(), String> {
    if ticket.len() != TICKET_LEN {
        return Err(format!("ticket com {} bytes, esperado {}", ticket.len(), TICKET_LEN));
    }
    let mut t = [0u8; TICKET_LEN];
    t.copy_from_slice(ticket);
    let pacote = encode_login_packet(&t);

    // Inline hook, não IAT: o cliente do RagnaLinK resolve o Winsock por
    // GetProcAddress e guarda o ponteiro, então chamadas não passam pela tabela
    // de imports — o hook de IAT instalava mas nunca disparava (o log da DLL
    // provou). O inline pega todo chamador. Os ordinais ficam por referência.
    let _ = (ORDINAL_SEND, ORDINAL_WSASEND);

    let send_real = match sys::inline_hook("ws2_32.dll", "send", hook_send as usize) {
        Ok(tramp) => Some(unsafe { std::mem::transmute::<usize, SendFn>(tramp) }),
        Err(e) => {
            sys::log_dll(&format!("netgate: send nao desviado ({})", e));
            None
        }
    };
    let wsasend_real = match sys::inline_hook("ws2_32.dll", "WSASend", hook_wsasend as usize) {
        Ok(tramp) => Some(unsafe { std::mem::transmute::<usize, WsaSendFn>(tramp) }),
        Err(e) => {
            sys::log_dll(&format!("netgate: WSASend nao desviado ({})", e));
            None
        }
    };

    if send_real.is_none() && wsasend_real.is_none() {
        return Err("nem send nem WSASend puderam ser desviados".to_string());
    }

    let mut guarda = ESTADO.lock().map_err(|_| "estado do netgate travado".to_string())?;
    *guarda = Some(Estado {
        pacote_0aaa: pacote,
        send_real,
        wsasend_real,
        carimbados: Vec::new(),
        orcamento_log: 40,
    });
    sys::log_dll("netgate instalado");
    Ok(())
}

/// Decide, para um buffer que está saindo num `socket`, se devemos antepor o
/// `0x0AAA`. Registra o opcode visto (dentro do orçamento de log) — é isto que
/// transforma "o hook não disparou" num diagnóstico em vez de um mistério.
///
/// Devolve `Some(pacote)` se é para antepor. Não segura o lock ao enviar.
fn avaliar(socket: usize, dados: &[u8]) -> Option<[u8; LOGIN_PACKET_LEN]> {
    let mut guarda = ESTADO.lock().ok()?;
    let est = guarda.as_mut()?;

    let op = packets::opcode_de(dados);
    if est.orcamento_log > 0 {
        est.orcamento_log -= 1;
        sys::log_dll(&format!(
            "envio socket={:x} opcode={} len={}",
            socket,
            op.map(|o| format!("0x{:04x}", o)).unwrap_or_else(|| "?".into()),
            dados.len()
        ));
    }

    let eh_login = matches!(op, Some(o) if packets::eh_pedido_de_login(o));
    if eh_login && !est.carimbados.contains(&socket) {
        est.carimbados.push(socket);
        sys::log_dll("netgate: login detectado, antepondo 0x0AAA");
        Some(est.pacote_0aaa)
    } else {
        None
    }
}

/// Substitui o ticket corrente por um fresco. Chamada pela `canal` quando um
/// `TICKET_RSP` chega. É isto que mantém o `0x0AAA` sempre dentro dos 30 s.
pub fn atualizar_ticket(ticket: &[u8]) -> bool {
    if ticket.len() != TICKET_LEN {
        return false;
    }
    let mut t = [0u8; TICKET_LEN];
    t.copy_from_slice(ticket);
    let pacote = encode_login_packet(&t);
    if let Ok(mut g) = ESTADO.lock() {
        if let Some(est) = g.as_mut() {
            est.pacote_0aaa = pacote;
            return true;
        }
    }
    false
}

/// O login já foi enviado? A `canal` usa isto para parar de renovar o ticket —
/// depois do login não há mais nada a proteger nesta conexão.
pub fn login_ja_saiu() -> bool {
    ESTADO
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|e| !e.carimbados.is_empty()))
        .unwrap_or(false)
}

fn pega_send_real() -> Option<SendFn> {
    ESTADO.lock().ok()?.as_ref()?.send_real
}

fn pega_wsasend_real() -> Option<WsaSendFn> {
    ESTADO.lock().ok()?.as_ref()?.wsasend_real
}

/// Envia o `0x0AAA` no socket, PELO `send` real (síncrono), e loga o retorno.
///
/// # Por que sempre pelo `send`, mesmo quando o login foi por `WSASend`
///
/// O `send` é síncrono: quando ele retorna, os 152 bytes já estão no buffer do
/// socket, garantidamente **antes** do packet de login que o hook vai deixar
/// passar em seguida. Um `WSASend` síncrono num socket overlapped tem
/// comportamento mais sutil, e foi por aí que a primeira tentativa falhou — o
/// servidor recebeu o login sem o ticket na frente. O `send` e o `WSASend`
/// funcionam no mesmo socket, então usar `send` para o prepend é sempre válido.
///
/// Loga o retorno: um `-1` (SOCKET_ERROR) explica na hora por que o ticket não
/// chegou, em vez de virar um "cliente nao enviou ticket" misterioso no servidor.
///
/// # SAFETY
/// `socket` é um socket válido e conectado (o login está saindo por ele).
unsafe fn disparar_0aaa(socket: usize, pacote: &[u8]) {
    if let Some(send_real) = pega_send_real() {
        let r = send_real(socket, pacote.as_ptr() as *const c_char, pacote.len() as c_int, 0);
        sys::log_dll(&format!("netgate: 0x0AAA enviado por send, ret={}", r));
        return;
    }
    if let Some(wsa) = pega_wsasend_real() {
        let nosso = WsaBuf {
            len: pacote.len() as u32,
            buf: pacote.as_ptr() as *mut c_char,
        };
        let mut enviados: u32 = 0;
        let r = wsa(socket, &nosso, 1, &mut enviados, 0, std::ptr::null_mut(), std::ptr::null_mut());
        sys::log_dll(&format!("netgate: 0x0AAA enviado por WSASend, ret={} enviados={}", r, enviados));
        return;
    }
    sys::log_dll("netgate: sem funcao de envio para o 0x0AAA");
}

// ===========================================================================
//  Os hooks
// ===========================================================================

/// Hook de `send`. Assinatura idêntica; o Winsock chama sem saber.
///
/// # SAFETY
/// `buf` aponta para `len` bytes válidos (contrato de `send`). Repassa tudo ao
/// `send` real; a única coisa a mais é, uma vez por login, enviar o `0x0AAA`.
unsafe extern "system" fn hook_send(
    socket: usize,
    buf: *const c_char,
    len: c_int,
    flags: c_int,
) -> c_int {
    let real = match pega_send_real() {
        Some(f) => f,
        None => return -1,
    };

    if !buf.is_null() && len >= 2 {
        // SAFETY: buf tem `len` bytes.
        let fatia = std::slice::from_raw_parts(buf as *const u8, len as usize);
        if let Some(pacote) = avaliar(socket, fatia) {
            // SAFETY: socket conectado (o login sai por ele).
            disparar_0aaa(socket, &pacote);
        }
    }
    // O packet original segue byte a byte inalterado.
    real(socket, buf, len, flags)
}

/// Hook de `WSASend`. É por aqui que o login do RagnaLinK realmente sai.
///
/// # SAFETY
/// `lpBuffers` aponta para `count` `WSABUF` válidos (contrato de `WSASend`).
/// Inspeciona o primeiro buffer; repassa a chamada inteira intacta.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_wsasend(
    socket: usize,
    lp_buffers: *const WsaBuf,
    count: u32,
    lp_enviados: *mut u32,
    flags: u32,
    lp_overlapped: *mut std::ffi::c_void,
    lp_completion: *mut std::ffi::c_void,
) -> c_int {
    let real = match pega_wsasend_real() {
        Some(f) => f,
        None => return -1,
    };

    if !lp_buffers.is_null() && count >= 1 {
        // SAFETY: lpBuffers aponta para `count` WSABUF; lemos o primeiro.
        let primeiro = &*lp_buffers;
        if !primeiro.buf.is_null() && primeiro.len >= 2 {
            // SAFETY: buf tem `len` bytes.
            let fatia = std::slice::from_raw_parts(primeiro.buf as *const u8, primeiro.len as usize);
            if let Some(pacote) = avaliar(socket, fatia) {
                // Antepõe pelo `send` síncrono (ver disparar_0aaa) — mais
                // confiável que um WSASend síncrono num socket overlapped, que
                // foi por onde a primeira tentativa escapou.
                // SAFETY: socket conectado.
                disparar_0aaa(socket, &pacote);
            }
        }
    }

    // A chamada original segue intacta — mesmos buffers, mesmo overlapped.
    real(socket, lp_buffers, count, lp_enviados, flags, lp_overlapped, lp_completion)
}
