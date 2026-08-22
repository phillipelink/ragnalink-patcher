//! Injeção da `rse_watchdog.dll` no processo suspenso do jogo, e o canal com ela.
//!
//! # 🚨 A parte menos testável do projeto
//!
//! Isto só funciona de verdade dentro de um Windows, com um processo alvo real.
//! Não há teste automatizado possível para injeção. O código é o clássico
//! `LoadLibrary` remoto, escrito com cuidado e comentado passo a passo — o
//! diagnóstico de campo vem do `rse_loader.log`.
//!
//! # A sequência, e por que cada passo existe
//!
//! ```text
//! 1. cria o pipe Loader<->DLL (servidor, duplex, modo mensagem)
//! 2. gera K_s e session_id (entropia do SO)
//! 3. escreve o caminho da DLL na memória do alvo  (VirtualAllocEx+WriteProcessMemory)
//! 4. CreateRemoteThread(LoadLibraryW, caminho)    -> a DLL carrega no alvo
//! 5. lê o HMODULE remoto do código de saída da thread
//! 6. escreve o blob de config (pipe, K_s, session_id) na memória do alvo
//! 7. calcula o endereço remoto de rse_configure e CreateRemoteThread nele
//! 8. HELLO -> espera HELLO_ACK  (a DLL provou que está viva)
//! ```
//!
//! Só depois do passo 8 o `main` dá `ResumeThread`. Um cliente retomado antes do
//! HELLO_ACK é um cliente rodando sem vigilância — a janela que o RSE existe para
//! fechar.
//!
//! # Como a DLL acha o endereço de `rse_configure`
//!
//! `CreateRemoteThread` só passa **um** argumento, e o `LoadLibraryW` já gasta
//! esse argumento com o caminho. Então a config vai por uma segunda
//! `CreateRemoteThread`, apontando direto para `rse_configure` no espaço do alvo.
//!
//! O endereço remoto se calcula por deslocamento: a DLL tem o mesmo layout nos
//! dois processos, então o RVA de `rse_configure` (endereço menos base do módulo)
//! é idêntico. O Loader carrega a **própria** cópia da DLL só para ler esse RVA,
//! e soma à base remota (que veio do passo 5). Em 32 bits o HMODULE cabe no
//! `DWORD` do código de saída, então isto é confiável.

#![cfg(windows)]

use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::auth;
use rse_protocol::crypto::{Direction, Key, OsRandom, RandomSource};
use rse_protocol::dll_config;
use rse_protocol::frame::{Opcode, Opener, Sealer};
use rse_protocol::version::{KEY_LEN, RSE_PROTOCOL, SESSION_ID_LEN};

use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{
    FreeLibrary, GetModuleHandleW, GetProcAddress, LoadLibraryExW, DONT_RESOLVE_DLL_REFERENCES,
};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, GetExitCodeThread};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{
    INFINITE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
use winapi::um::fileapi::{ReadFile, WriteFile};
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Handle de processo emprestado (não fecha no Drop): vem do `PROCESS_INFORMATION`
/// que o `jogo.rs` já é dono. Aqui só usamos.
#[derive(Clone, Copy)]
pub struct AlvoProcesso(pub HANDLE);

/// Tudo que o `main` precisa manter vivo enquanto o jogo roda.
pub struct CanalDll {
    pipe: PipeDuplex,
    opener: Opener,
    sealer: Sealer,
    /// Para atender aos `TICKET_REQ` da DLL: cunhar um ticket fresco é falar de
    /// novo com o Auth Service, e o Loader é quem tem a credencial de sessão.
    auth_url: String,
    credencial: String,
    client_hash: String,
}

/// Injeta a DLL, faz o handshake, e devolve o canal pronto para o heartbeat.
///
/// `dll_path` e `auth_url` já vêm resolvidos pelo `main`. `alvo` é o handle do
/// processo suspenso (de `CreateProcessW`). `credencial`/`client_hash` ficam
/// guardados para renovar o ticket quando a DLL pedir (TICKET_REQ).
pub fn injetar_e_apertar_mao(
    alvo: AlvoProcesso,
    dll_path: &Path,
    ticket: &[u8],
    auth_url: &str,
    credencial: &str,
    client_hash: &str,
) -> Result<CanalDll> {
    if !dll_path.is_absolute() {
        bail!("caminho da DLL precisa ser absoluto: {}", dll_path.display());
    }
    if !dll_path.exists() {
        bail!(
            "nao encontrei a rse_watchdog.dll em {}. Ela vai na mesma pasta do \
             rse_loader.exe.",
            dll_path.display()
        );
    }

    // 1. pipe duplex, criado ANTES de a DLL existir para o nome já valer quando
    //    ela conectar.
    let nome_pipe = nome_de_pipe_aleatorio()?;
    let pipe = PipeDuplex::criar(&nome_pipe).context("criando o pipe Loader<->DLL")?;

    // 2. K_s e session_id.
    let mut ks = [0u8; KEY_LEN];
    let mut sid = [0u8; SESSION_ID_LEN];
    OsRandom
        .fill(&mut ks)
        .and_then(|_| OsRandom.fill(&mut sid))
        .map_err(|_| anyhow!("o sistema nao forneceu entropia para a K_s"))?;
    let session_key = Key::from_bytes(ks);

    // 3+4. injeta a DLL e lê a base remota.
    let base_remota = carregar_dll_remota(alvo, dll_path).context("carregando a DLL no alvo")?;
    log::info!("rse_watchdog.dll carregada no alvo, base=0x{:x}", base_remota);

    // 6. escreve a config na memória do alvo.
    let blob = dll_config::serialize(&nome_pipe, &session_key, &sid)
        .map_err(|e| anyhow!("montando a config da DLL: {}", e))?;
    let cfg_remota = escrever_no_alvo(alvo, &blob).context("escrevendo a config no alvo")?;

    // 7. chama rse_configure(cfg_remota) no alvo.
    let addr_configure = endereco_remoto_de(dll_path, base_remota, "rse_configure")
        .context("localizando rse_configure na DLL")?;
    let codigo = rodar_thread_remota(alvo, addr_configure, cfg_remota)
        .context("chamando rse_configure no alvo")?;
    if codigo != 0 {
        bail!(
            "rse_configure devolveu {} (1=config ilegivel, 2=malformada, 3=sem thread)",
            codigo
        );
    }
    // A config já foi lida pela DLL; libera a região no alvo.
    liberar_no_alvo(alvo, cfg_remota);

    // 8. handshake.
    let (l2d, d2l) = rse_protocol::crypto::derive_channel_keys(&session_key, &sid);
    let mut sealer = Sealer::new(&l2d, Direction::LoaderToDll);
    let mut opener = Opener::new(&d2l, Direction::DllToLoader);

    pipe.esperar_conexao().context("a DLL nao conectou no pipe")?;
    apertar_mao(&pipe, &mut sealer, &mut opener, ticket).context("handshake com a DLL")?;

    Ok(CanalDll {
        pipe,
        opener,
        sealer,
        auth_url: auth_url.to_string(),
        credencial: credencial.to_string(),
        client_hash: client_hash.to_string(),
    })
}

impl CanalDll {
    /// Responde heartbeats até o jogo fechar ou a DLL sumir.
    ///
    /// Bloqueia. Roda depois do `ResumeThread`, na thread principal do Loader —
    /// que a partir daí não tem mais nada a fazer senão vigiar.
    pub fn manter_heartbeat(&mut self) -> Result<()> {
        // Kill-switch em sessão aberta. Uma thread consulta a política a cada 60 s
        // e, se ela virar 'off', seta esta flag. A consulta fica FORA do laço de
        // propósito: o GET pode levar segundos, e o laço não pode ficar sem
        // responder à DLL — 3 batimentos sem ACK (15 s) e ela se mata. A thread
        // morre com o processo do Loader quando a vigilância retorna.
        let desligar = Arc::new(AtomicBool::new(false));
        {
            let desligar = desligar.clone();
            let url = self.auth_url.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(60));
                match auth::consultar_politica(&url) {
                    Ok(p) if p.loader_desligado() => {
                        log::warn!("kill-switch: a politica passou para 'off'");
                        desligar.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(_) => {}
                    Err(e) => log::debug!("consulta de politica falhou (ignorando): {:#}", e),
                }
            });
        }

        let mut mandou_shutdown = false;
        loop {
            // Kill-switch ativado no meio da sessão: manda a DLL recuar LIMPO
            // (SHUTDOWN) e SEGUE servindo o pipe. A DLL, ao ler o SHUTDOWN, encerra
            // a própria thread sem derrubar o jogo (`canal.rs` devolve Ok nesse
            // caso) e fecha o pipe — então o `ler` abaixo retorna Err e saímos
            // normal. Mandar e sair na hora seria uma corrida: o pipe fecharia
            // antes de a DLL ler o SHUTDOWN, ela trataria como perda do Loader e se
            // mataria — o oposto do que o kill-switch quer. Por isso: manda UMA vez
            // e continua servindo até a DLL encerrar por conta própria.
            if desligar.load(Ordering::SeqCst) && !mandou_shutdown {
                log::warn!("kill-switch ativo — mandando a DLL recuar (SHUTDOWN); o jogo segue");
                match self.sealer.seal(Opcode::Shutdown, &[]) {
                    Ok(f) => {
                        let _ = self.pipe.escrever(&f);
                    }
                    Err(e) => log::warn!("nao consegui cifrar o SHUTDOWN do kill-switch: {}", e),
                }
                mandou_shutdown = true;
            }

            let bruto = match self.pipe.ler() {
                Ok(b) => b,
                // Pipe fechado = jogo terminou (ou a DLL recuou pelo kill-switch).
                Err(_) => {
                    log::info!("canal com a DLL encerrado (o jogo fechou)");
                    return Ok(());
                }
            };

            let frame = match self.opener.open(&bruto) {
                Ok(f) => f,
                Err(e) => {
                    log::warn!("frame da DLL nao autenticou: {}", e);
                    continue;
                }
            };

            if frame.opcode_raw == Opcode::Heartbeat.as_u8() {
                let ack = self
                    .sealer
                    .seal(Opcode::HeartbeatAck, &[])
                    .map_err(|e| anyhow!("cifrando HEARTBEAT_ACK: {}", e))?;
                if self.pipe.escrever(&ack).is_err() {
                    log::info!("nao consegui responder heartbeat; a DLL sumiu");
                    return Ok(());
                }
            } else if frame.opcode_raw == Opcode::TicketReq.as_u8() {
                // A DLL quer um ticket fresco (o do arranque pode ter expirado).
                // Cunhamos um novo falando com o Auth Service — o Loader tem a
                // credencial de sessão. Falha aqui NÃO é fatal: respondemos
                // TICKET_RSP de falha e a DLL segue com o ticket anterior.
                let resposta = match auth::pedir_ticket_com_hash(
                    &self.auth_url,
                    &self.credencial,
                    &self.client_hash,
                ) {
                    Ok(t) => {
                        log::info!("ticket renovado para a DLL");
                        montar_ticket_rsp_ok(&t.bytes)
                    }
                    Err(e) => {
                        log::warn!("nao consegui renovar o ticket: {:#}", e);
                        vec![1u8] // status != 0, sem ticket
                    }
                };
                let frame = self
                    .sealer
                    .seal(Opcode::TicketRsp, &resposta)
                    .map_err(|e| anyhow!("cifrando TICKET_RSP: {}", e))?;
                if self.pipe.escrever(&frame).is_err() {
                    log::info!("nao consegui responder TICKET_REQ; a DLL sumiu");
                    return Ok(());
                }
            } else if frame.opcode_raw == Opcode::Shutdown.as_u8() {
                log::info!("a DLL pediu shutdown");
                return Ok(());
            }
            // Fase 5c: REPORT é tratado aqui.
        }
    }
}

/// Payload do TICKET_RSP de sucesso: `[status=0][ticket]`. Espelha
/// `mensagens::montar_ticket_rsp_ok` da DLL — mantido aqui para o Loader não
/// depender do crate da DLL.
fn montar_ticket_rsp_ok(ticket: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + ticket.len());
    p.push(0);
    p.extend_from_slice(ticket);
    p
}

// ===========================================================================
//  Passos individuais
// ===========================================================================

fn nome_de_pipe_aleatorio() -> Result<String> {
    let mut bytes = [0u8; 16];
    OsRandom
        .fill(&mut bytes)
        .map_err(|_| anyhow!("sem entropia para o nome do pipe"))?;
    Ok(format!("rse-dll-{}", rse_protocol::crypto::to_hex(&bytes)))
}

/// Passos 3–5: escreve o caminho no alvo, chama `LoadLibraryW` remoto, e devolve
/// a base do módulo carregado.
fn carregar_dll_remota(alvo: AlvoProcesso, dll_path: &Path) -> Result<u32> {
    let caminho_w = wide(dll_path.to_str().context("caminho da DLL nao e UTF-8")?);
    let bytes = unsafe {
        std::slice::from_raw_parts(
            caminho_w.as_ptr() as *const u8,
            caminho_w.len() * std::mem::size_of::<u16>(),
        )
    };
    let remoto = escrever_no_alvo(alvo, bytes).context("escrevendo o caminho da DLL")?;

    // Endereço de LoadLibraryW. kernel32 fica na MESMA base em todos os processos
    // de uma sessão (o Windows garante isso para as DLLs conhecidas), então o
    // endereço local vale no alvo.
    let load_library = endereco_local("kernel32.dll", "LoadLibraryW")
        .context("localizando LoadLibraryW")?;

    let codigo = rodar_thread_remota(alvo, load_library, remoto)
        .context("chamando LoadLibraryW no alvo")?;
    liberar_no_alvo(alvo, remoto);

    if codigo == 0 {
        bail!("LoadLibraryW no alvo devolveu base 0 — a DLL nao carregou (arquitetura errada? dependencia faltando?)");
    }
    Ok(codigo)
}

/// `VirtualAllocEx` + `WriteProcessMemory`: copia `dados` para o alvo, devolve o
/// endereço remoto.
fn escrever_no_alvo(alvo: AlvoProcesso, dados: &[u8]) -> Result<LPVOID> {
    // SAFETY: alvo.0 é um handle de processo válido com direito de escrita
    // (CreateProcessW dá acesso total ao criador).
    let remoto = unsafe {
        VirtualAllocEx(
            alvo.0,
            ptr::null_mut(),
            dados.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remoto.is_null() {
        let e = unsafe { GetLastError() };
        bail!("VirtualAllocEx falhou (erro {})", e);
    }

    let mut escritos = 0usize;
    // SAFETY: remoto tem dados.len() bytes recém-alocados; dados é válido.
    let ok = unsafe {
        WriteProcessMemory(
            alvo.0,
            remoto,
            dados.as_ptr() as *const _,
            dados.len(),
            &mut escritos,
        )
    };
    if ok == FALSE || escritos != dados.len() {
        let e = unsafe { GetLastError() };
        unsafe { VirtualFreeEx(alvo.0, remoto, 0, MEM_RELEASE) };
        bail!("WriteProcessMemory falhou (erro {})", e);
    }
    Ok(remoto)
}

fn liberar_no_alvo(alvo: AlvoProcesso, remoto: LPVOID) {
    // SAFETY: remoto veio de VirtualAllocEx neste mesmo processo alvo.
    unsafe { VirtualFreeEx(alvo.0, remoto, 0, MEM_RELEASE) };
}

/// `CreateRemoteThread` apontando para `func`, com `arg`, e espera terminar.
/// Devolve o código de saída da thread (para LoadLibrary = HMODULE em 32 bits).
fn rodar_thread_remota(alvo: AlvoProcesso, func: usize, arg: LPVOID) -> Result<u32> {
    type ThreadStart = unsafe extern "system" fn(LPVOID) -> DWORD;
    // SAFETY: func é o endereço de uma função com assinatura de
    // LPTHREAD_START_ROUTINE, no espaço do alvo.
    let start: ThreadStart = unsafe { std::mem::transmute::<usize, ThreadStart>(func) };

    // SAFETY: alvo válido; start aponta para código executável no alvo; arg é
    // memória válida no alvo.
    let h = unsafe {
        CreateRemoteThread(
            alvo.0,
            ptr::null_mut(),
            0,
            Some(start),
            arg,
            0,
            ptr::null_mut(),
        )
    };
    if h.is_null() {
        let e = unsafe { GetLastError() };
        bail!("CreateRemoteThread falhou (erro {})", e);
    }

    // Espera a thread remota terminar. O prazo é generoso: LoadLibrary pode puxar
    // dependências. INFINITE é seguro porque o alvo está suspenso e a thread que
    // rodamos é curta por construção.
    let _ = unsafe { WaitForSingleObject(h, INFINITE) };

    let mut codigo: DWORD = 0;
    // SAFETY: h é um handle de thread válido; codigo recebe a saída.
    let ok = unsafe { GetExitCodeThread(h, &mut codigo) };
    unsafe { CloseHandle(h) };
    if ok == FALSE {
        let e = unsafe { GetLastError() };
        bail!("GetExitCodeThread falhou (erro {})", e);
    }
    Ok(codigo)
}

/// Endereço de uma função exportada por um módulo JÁ CARREGADO neste processo.
fn endereco_local(modulo: &str, funcao: &str) -> Result<usize> {
    let mod_w = wide(modulo);
    // SAFETY: mod_w termina em NUL.
    let h = unsafe { GetModuleHandleW(mod_w.as_ptr()) };
    if h.is_null() {
        bail!("{} nao esta carregado", modulo);
    }
    endereco_em(h, funcao)
}

/// Endereço REMOTO de uma função da nossa DLL: carrega a própria cópia só para
/// medir o deslocamento (RVA) e soma à base remota.
fn endereco_remoto_de(dll_path: &Path, base_remota: u32, funcao: &str) -> Result<usize> {
    let path_w = wide(dll_path.to_str().context("caminho da DLL nao e UTF-8")?);
    // DONT_RESOLVE_DLL_REFERENCES: só queremos o layout, não rodar a DLL aqui no
    // Loader. Isso NÃO executa DllMain.
    // SAFETY: path_w termina em NUL.
    let modulo = unsafe { LoadLibraryExW(path_w.as_ptr(), ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES) };
    if modulo.is_null() {
        let e = unsafe { GetLastError() };
        bail!("nao consegui carregar a propria copia da DLL (erro {})", e);
    }

    let resultado = (|| {
        let addr_local = endereco_em(modulo, funcao)?;
        let base_local = modulo as usize;
        let rva = addr_local
            .checked_sub(base_local)
            .ok_or_else(|| anyhow!("RVA negativo — layout inesperado"))?;
        Ok(base_remota as usize + rva)
    })();

    // SAFETY: modulo veio de LoadLibraryExW e ainda não foi liberado.
    unsafe { FreeLibrary(modulo) };
    resultado
}

fn endereco_em(modulo: HMODULE, funcao: &str) -> Result<usize> {
    let nome = std::ffi::CString::new(funcao).context("nome de funcao com NUL")?;
    // SAFETY: modulo válido; nome termina em NUL.
    let addr = unsafe { GetProcAddress(modulo, nome.as_ptr()) };
    if addr.is_null() {
        bail!("a DLL nao exporta {}", funcao);
    }
    Ok(addr as usize)
}

fn apertar_mao(
    pipe: &PipeDuplex,
    sealer: &mut Sealer,
    opener: &mut Opener,
    ticket: &[u8],
) -> Result<()> {
    // HELLO carrega o ticket: a DLL vai precisar dele na Fase 5b para o 0x0AAA.
    // Entregá-lo já no HELLO evita um round-trip TICKET_REQ/TICKET_RSP no caminho
    // quente (o jogador esperando a tela de login).
    let mut payload = Vec::with_capacity(1 + ticket.len());
    payload.push(RSE_PROTOCOL);
    payload.extend_from_slice(ticket);

    let hello = sealer
        .seal(Opcode::Hello, &payload)
        .map_err(|e| anyhow!("cifrando HELLO: {}", e))?;
    pipe.escrever(&hello).context("enviando HELLO")?;

    let bruto = pipe.ler().context("esperando HELLO_ACK")?;
    let frame = opener
        .open(&bruto)
        .map_err(|e| anyhow!("HELLO_ACK nao autenticou ({}) — K_s divergente?", e))?;
    if frame.opcode_raw != Opcode::HelloAck.as_u8() {
        bail!("esperava HELLO_ACK, veio opcode 0x{:02x}", frame.opcode_raw);
    }
    log::info!("HELLO_ACK recebido — a DLL esta viva e o canal cifrado funciona");
    Ok(())
}

// ===========================================================================
//  Pipe duplex do lado servidor
// ===========================================================================

struct PipeDuplex {
    h: HANDLE,
}

// SAFETY: handle opaco, dono único.
unsafe impl Send for PipeDuplex {}

impl Drop for PipeDuplex {
    fn drop(&mut self) {
        if self.h != INVALID_HANDLE_VALUE && !self.h.is_null() {
            // SAFETY: dono único.
            unsafe {
                DisconnectNamedPipe(self.h);
                CloseHandle(self.h);
            }
        }
    }
}

impl PipeDuplex {
    fn criar(nome: &str) -> Result<PipeDuplex> {
        let caminho = wide(&format!(r"\\.\pipe\{}", nome));
        // Duplex + mensagem: os dois lados leem e escrevem, e cada mensagem é um
        // frame inteiro. lpSecurityAttributes NULL = DACL padrão, que restringe
        // ao usuário criador — o que se quer.
        // SAFETY: caminho termina em NUL; demais parâmetros são constantes.
        let h = unsafe {
            CreateNamedPipeW(
                caminho.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                9000,
                9000,
                0,
                ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let e = unsafe { GetLastError() };
            bail!("CreateNamedPipeW falhou (erro {})", e);
        }
        Ok(PipeDuplex { h })
    }

    fn esperar_conexao(&self) -> Result<()> {
        // SAFETY: handle válido; sem OVERLAPPED, bloqueia até a DLL conectar.
        let ok = unsafe { ConnectNamedPipe(self.h, ptr::null_mut()) };
        if ok == FALSE {
            let e = unsafe { GetLastError() };
            const ERROR_PIPE_CONNECTED: u32 = 535;
            if e != ERROR_PIPE_CONNECTED {
                bail!("ConnectNamedPipe falhou (erro {})", e);
            }
        }
        Ok(())
    }

    fn ler(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 9000];
        let mut lidos: DWORD = 0;
        // SAFETY: handle válido; buf tem espaço para buf.len().
        let ok = unsafe {
            ReadFile(
                self.h,
                buf.as_mut_ptr() as *mut _,
                buf.len() as DWORD,
                &mut lidos,
                ptr::null_mut(),
            )
        };
        if ok == FALSE {
            let e = unsafe { GetLastError() };
            bail!("ReadFile no pipe falhou (erro {})", e);
        }
        buf.truncate(lidos as usize);
        Ok(buf)
    }

    fn escrever(&self, dados: &[u8]) -> Result<()> {
        let mut escritos: DWORD = 0;
        // SAFETY: handle válido; dados é válido.
        let ok = unsafe {
            WriteFile(
                self.h,
                dados.as_ptr() as *const _,
                dados.len() as DWORD,
                &mut escritos,
                ptr::null_mut(),
            )
        };
        if ok == FALSE {
            let e = unsafe { GetLastError() };
            bail!("WriteFile no pipe falhou (erro {})", e);
        }
        if escritos as usize != dados.len() {
            bail!("escrevi {} de {} bytes no pipe", escritos, dados.len());
        }
        Ok(())
    }
}
