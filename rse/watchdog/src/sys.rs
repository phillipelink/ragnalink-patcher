//! Toda a conversa com a API do Windows fica aqui.
//!
//! Concentrar o `unsafe` num arquivo so e uma decisao deliberada: o resto da DLL
//! (`canal`, `mensagens`) e Rust seguro e testavel em qualquer maquina. Se algo
//! der errado com um handle ou um ponteiro, o problema esta neste arquivo, e so
//! nele.

#![cfg(windows)]

use std::ptr;

use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetModuleFileNameW, GetModuleHandleW};
use winapi::um::namedpipeapi::WaitNamedPipeW;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId};
use winapi::um::synchapi::Sleep;
use winapi::um::namedpipeapi::SetNamedPipeHandleState;
use winapi::um::winnt::{
    HANDLE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn pid_atual() -> u32 {
    // SAFETY: chamada sem parametros, nunca falha.
    unsafe { GetCurrentProcessId() }
}

pub fn tid_atual() -> u32 {
    // SAFETY: idem.
    unsafe { GetCurrentThreadId() }
}

/// Endereco base do modulo principal do processo (o proprio Ragexe).
///
/// So para diagnostico — vai no HELLO_ACK. `GetModuleHandleW(NULL)` devolve a
/// base do executavel, que e um numero estavel que ajuda a casar este processo
/// com o que o Loader criou.
pub fn base_do_modulo() -> u64 {
    // SAFETY: NULL pede o modulo do proprio processo; sempre existe.
    let h: HMODULE = unsafe { GetModuleHandleW(ptr::null()) };
    h as usize as u64
}

/// Caminho do executavel do processo hospedeiro (o proprio Ragexe).
///
/// `GetModuleFileNameW(NULL)` devolve o caminho do modulo principal lido de
/// DENTRO do processo — nao um caminho que alguem passou por fora. E o arquivo
/// que a integridade da Fase 5c confere.
pub fn caminho_do_exe() -> Option<String> {
    let mut buf = [0u16; 260]; // MAX_PATH
    // SAFETY: buffer valido; NULL = modulo principal. `n` = quantos u16 escritos.
    let n = unsafe { GetModuleFileNameW(ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return None; // falhou, ou o caminho nao coube (caso raro): sem report
    }
    Some(String::from_utf16_lossy(&buf[..n as usize]))
}

pub fn dormir_ms(ms: u32) {
    // SAFETY: Sleep nao tem como falhar.
    unsafe { Sleep(ms) }
}

/// Encerra o proprio processo — o `SelfKill` da maquina de estados da DLL.
///
/// Codigo de saida 0xB5E (RSE... mais ou menos) para o encerramento ser
/// distinguivel de uma saida normal do jogo num rastreio.
pub fn matar_o_proprio_processo() -> ! {
    use winapi::um::processthreadsapi::TerminateProcess;
    // SAFETY: GetCurrentProcess devolve um pseudo-handle valido; TerminateProcess
    // com ele nao retorna.
    unsafe {
        TerminateProcess(GetCurrentProcess(), 0xB5E);
    }
    // TerminateProcess nao retorna, mas o compilador nao sabe disso.
    loop {
        dormir_ms(1000);
    }
}

/// Cliente de named pipe, no lado da DLL.
pub struct Pipe {
    h: HANDLE,
}

// SAFETY: o handle e um valor opaco valido em todo o processo; esta estrutura e
// dona unica dele.
unsafe impl Send for Pipe {}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.h != INVALID_HANDLE_VALUE && !self.h.is_null() {
            // SAFETY: dono unico, handle ainda aberto.
            unsafe { CloseHandle(self.h) };
        }
    }
}

impl Pipe {
    /// Conecta ao pipe do Loader, tentando ate o prazo.
    pub fn conectar(nome: &str, timeout_ms: u32) -> Result<Pipe, String> {
        let caminho = if nome.starts_with(r"\\.\pipe\") {
            nome.to_string()
        } else {
            format!(r"\\.\pipe\{}", nome)
        };
        let caminho_w = wide(&caminho);
        let inicio = std::time::Instant::now();
        let prazo = std::time::Duration::from_millis(timeout_ms as u64);

        loop {
            // SAFETY: caminho_w termina em NUL; demais parametros sao constantes
            // ou nulos aceitos pela assinatura.
            let h = unsafe {
                CreateFileW(
                    caminho_w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                let pipe = Pipe { h };
                pipe.modo_mensagem()?;
                return Ok(pipe);
            }

            // SAFETY: leitura do ultimo erro da thread.
            let erro = unsafe { GetLastError() };
            if inicio.elapsed() >= prazo {
                return Err(format!("pipe {} indisponivel (erro {})", caminho, erro));
            }
            // SAFETY: mesma string com NUL.
            unsafe { WaitNamedPipeW(caminho_w.as_ptr(), 200) };
        }
    }

    /// Poe o pipe em modo mensagem: cada `ReadFile` devolve um frame inteiro, que
    /// e o que o `frame.rs` espera. Sem isto, um `ReadFile` poderia cortar um
    /// frame ao meio ou juntar dois.
    fn modo_mensagem(&self) -> Result<(), String> {
        let mut modo: DWORD = winapi::um::winbase::PIPE_READMODE_MESSAGE;
        // SAFETY: handle valido; passamos um ponteiro para um DWORD valido.
        let ok = unsafe {
            SetNamedPipeHandleState(self.h, &mut modo, ptr::null_mut(), ptr::null_mut())
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro.
            let erro = unsafe { GetLastError() };
            return Err(format!("SetNamedPipeHandleState falhou (erro {})", erro));
        }
        Ok(())
    }

    /// Le um frame. Em modo mensagem, um `ReadFile` = um frame.
    ///
    /// O `timeout_ms` aqui e informativo: o prazo de verdade e o do proprio pipe,
    /// configurado pelo Loader ao criar. Mantido na assinatura para o chamador
    /// documentar a intencao, e para uma versao futura com pipe assincrono.
    pub fn ler(&self, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        // Frame maximo: cabecalho(24) + payload(8192) + tag(16) = 8232. Um buffer
        // um pouco maior cobre com folga.
        let mut buf = vec![0u8; 9000];
        let mut lidos: DWORD = 0;
        // SAFETY: handle valido; buf tem espaco para `buf.len()` bytes; lidos
        // recebe a contagem.
        let ok = unsafe {
            ReadFile(
                self.h,
                buf.as_mut_ptr() as *mut _,
                buf.len() as DWORD,
                &mut lidos,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro.
            let erro = unsafe { GetLastError() };
            return Err(format!("ReadFile no pipe falhou (erro {})", erro));
        }
        buf.truncate(lidos as usize);
        Ok(buf)
    }

    pub fn escrever(&self, dados: &[u8]) -> Result<(), String> {
        let mut escritos: DWORD = 0;
        // SAFETY: handle valido; dados aponta para memoria valida de dados.len().
        let ok = unsafe {
            WriteFile(
                self.h,
                dados.as_ptr() as *const _,
                dados.len() as DWORD,
                &mut escritos,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: leitura do ultimo erro.
            let erro = unsafe { GetLastError() };
            return Err(format!("WriteFile no pipe falhou (erro {})", erro));
        }
        if escritos as usize != dados.len() {
            return Err(format!("escrevi {} de {} bytes", escritos, dados.len()));
        }
        Ok(())
    }
}

// ===========================================================================
//  Inline hook (detour de 5 bytes)
// ===========================================================================

/// Enxerta um desvio no INICIO da funcao `func` de `modulo` — pega TODO chamador,
/// inclusive quem resolveu a funcao por `GetProcAddress` e guardou o ponteiro
/// (que e o que o cliente do RagnaLinK faz, e por isso o hook de IAT nao pegou).
/// Devolve o endereco de um **trampolim** que executa os bytes originais e volta
/// — o chamador usa isso como se fosse a funcao verdadeira.
///
/// # Como, e por que e seguro nesta funcao especifica
///
/// A tecnica e o "detour de 5 bytes": sobrescreve o comeco da funcao com um
/// `jmp` de 5 bytes para o nosso codigo. O perigo classico e cortar uma
/// instrucao ao meio. Fugimos disso exigindo o **prologo hotpatch** da Microsoft:
/// funcoes de DLL de sistema comecam com `mov edi, edi` (bytes `8B FF`), que
/// existe exatamente para permitir um desvio de 5 bytes seguro — a Microsoft
/// garante que os 5 primeiros bytes (`8B FF 55 8B EC` = mov edi,edi; push ebp;
/// mov ebp,esp) podem ser trocados.
///
/// Se o prologo NAO for esse, esta funcao **nao toca em nada** e devolve erro com
/// os bytes que viu. Sem desmontador embutido, mexer num prologo desconhecido
/// seria justamente o que trava o jogo — entao nao mexemos.
/// Endereco de um simbolo exportado por um modulo **ja carregado**.
///
/// `None` quando o modulo nao esta no processo ou nao exporta o nome. Nao
/// carrega DLL nenhuma de proposito: se o modulo nao esta ai, a resposta certa e
/// "nao sei", e nao trazer uma DLL nova para dentro do processo do jogo so para
/// responder uma pergunta de diagnostico.
pub fn endereco_de(modulo: &str, func: &str) -> Option<usize> {
    use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};

    let mod_w = wide(modulo);
    // SAFETY: mod_w termina em NUL.
    let h = unsafe { GetModuleHandleW(mod_w.as_ptr()) };
    if h.is_null() {
        return None;
    }
    let nome = std::ffi::CString::new(func).ok()?;
    // SAFETY: h valido; nome termina em NUL.
    let p = unsafe { GetProcAddress(h, nome.as_ptr()) } as usize;
    if p == 0 {
        None
    } else {
        Some(p)
    }
}

pub fn inline_hook(modulo: &str, func: &str, novo: usize) -> Result<usize, String> {
    use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
    use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
    use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ,
    };

    const TAM_DESVIO: usize = 5; // E9 + rel32

    let mod_w = wide(modulo);
    // SAFETY: mod_w termina em NUL; ws2_32 ja esta carregado no processo.
    let h = unsafe { GetModuleHandleW(mod_w.as_ptr()) };
    if h.is_null() {
        return Err(format!("{} nao esta carregado", modulo));
    }
    let nome = std::ffi::CString::new(func).map_err(|_| "nome com NUL".to_string())?;
    // SAFETY: h valido; nome termina em NUL.
    let alvo = unsafe { GetProcAddress(h, nome.as_ptr()) } as usize;
    if alvo == 0 {
        return Err(format!("{} nao exporta {}", modulo, func));
    }

    // Le os 5 primeiros bytes do alvo.
    // SAFETY: `alvo` e o inicio de uma funcao exportada; 5 bytes sao legiveis.
    let prologo: [u8; TAM_DESVIO] = unsafe { std::ptr::read(alvo as *const [u8; TAM_DESVIO]) };

    // Exige o prologo hotpatch. `8B FF` = mov edi, edi.
    if prologo[0] != 0x8B || prologo[1] != 0xFF {
        return Err(format!(
            "prologo de {} nao e hotpatch (bytes {:02x} {:02x} {:02x} {:02x} {:02x}) — nao mexi",
            func, prologo[0], prologo[1], prologo[2], prologo[3], prologo[4]
        ));
    }

    // Trampolim: [5 bytes originais][jmp de volta para alvo+5]. Executavel.
    let tam_tramp = TAM_DESVIO + 5;
    // SAFETY: aloca memoria nova, executavel e gravavel, so nossa.
    let tramp = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            tam_tramp,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as usize;
    if tramp == 0 {
        return Err("VirtualAlloc do trampolim falhou".to_string());
    }

    // SAFETY: tramp tem tam_tramp bytes nossos.
    unsafe {
        // 1. copia os 5 bytes originais.
        std::ptr::copy_nonoverlapping(prologo.as_ptr(), tramp as *mut u8, TAM_DESVIO);
        // 2. jmp de tramp+5 para alvo+5.
        *((tramp + TAM_DESVIO) as *mut u8) = 0xE9;
        let rel_volta = (alvo + TAM_DESVIO)
            .wrapping_sub(tramp + TAM_DESVIO + 5) as i32;
        std::ptr::write_unaligned((tramp + TAM_DESVIO + 1) as *mut i32, rel_volta);
    }

    // Patcha o alvo: jmp para `novo`.
    let mut antiga: u32 = 0;
    // SAFETY: 5 bytes no inicio da funcao alvo.
    let ok = unsafe {
        VirtualProtect(alvo as *mut _, TAM_DESVIO, PAGE_EXECUTE_READWRITE, &mut antiga)
    };
    if ok == 0 {
        let e = unsafe { GetLastError() };
        return Err(format!("VirtualProtect do alvo falhou (erro {})", e));
    }
    // SAFETY: alvo agora e gravavel; escrevemos o E9 + rel32.
    unsafe {
        *(alvo as *mut u8) = 0xE9;
        let rel_ida = novo.wrapping_sub(alvo + 5) as i32;
        std::ptr::write_unaligned((alvo + 1) as *mut i32, rel_ida);
    }
    // Restaura a protecao (volta a executavel-so-leitura).
    let mut lixo: u32 = 0;
    // SAFETY: mesma regiao.
    unsafe { VirtualProtect(alvo as *mut _, TAM_DESVIO, PAGE_EXECUTE_READ, &mut lixo) };

    // O cache de instrucoes precisa saber que o codigo mudou.
    // SAFETY: pseudo-handle do processo; regiao valida.
    unsafe { FlushInstructionCache(GetCurrentProcess(), alvo as *const _, TAM_DESVIO) };

    log_dll(&format!("inline_hook: {} desviado (trampolim em 0x{:x})", func, tramp));
    Ok(tramp)
}

// ===========================================================================
//  Hook de IAT
// ===========================================================================

/// Troca, na Import Address Table do modulo principal (o Ragexe), o endereco da
/// funcao `func` importada de `modulo` pelo `novo`. Devolve o endereco ORIGINAL,
/// para o chamador repassar as chamadas.
///
/// # Como funciona
///
/// Todo executavel PE tem uma tabela de imports: para cada DLL de que depende,
/// uma lista de funcoes, e um slot por funcao onde o carregador do Windows
/// escreveu o endereco real no momento da carga. Trocar o valor do slot
/// redireciona toda chamada que passa por ele. Nao reescrevemos nenhuma
/// instrucao — so um ponteiro de dados —, o que torna isto seguro e reversivel.
///
/// # SAFETY interno
///
/// Anda por ponteiros crus dentro da imagem do proprio processo, guiado pelos
/// cabecalhos PE. Cada passo confere limites como pode; a estrutura de um PE
/// carregado e estavel, entao os offsets sao os que a especificacao define.
pub fn hook_iat(modulo: &str, func: &str, ordinal: u16, novo: usize) -> Result<usize, String> {
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::{
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
        IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS32, IMAGE_NT_SIGNATURE,
        IMAGE_ORDINAL_FLAG32, IMAGE_THUNK_DATA32, PAGE_READWRITE,
    };

    // Base do Ragexe.
    // SAFETY: NULL pede o modulo do proprio processo; sempre existe.
    let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;
    if base == 0 {
        return Err("GetModuleHandleW(NULL) devolveu 0".to_string());
    }

    // SAFETY: `base` e a imagem carregada; o DOS header esta no offset 0.
    let dos = base as *const IMAGE_DOS_HEADER;
    let dos_ref = unsafe { &*dos };
    if dos_ref.e_magic != IMAGE_DOS_SIGNATURE {
        return Err("assinatura DOS invalida".to_string());
    }

    // SAFETY: e_lfanew aponta para os NT headers dentro da imagem.
    let nt = (base + dos_ref.e_lfanew as usize) as *const IMAGE_NT_HEADERS32;
    let nt_ref = unsafe { &*nt };
    if nt_ref.Signature != IMAGE_NT_SIGNATURE {
        return Err("assinatura NT invalida".to_string());
    }

    let dir = nt_ref.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
    if dir.VirtualAddress == 0 {
        return Err("modulo sem tabela de imports".to_string());
    }

    let alvo_dll = modulo.to_ascii_lowercase();
    let mut desc = (base + dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

    // Cada descriptor e uma DLL importada; a lista termina num descriptor zerado.
    loop {
        // SAFETY: caminhamos a lista de descriptors da tabela de imports.
        let d = unsafe { &*desc };
        // O campo Name (RVA) zerado marca o fim.
        // SAFETY: acesso ao union OriginalFirstThunk/Characteristics.
        let name_rva = d.Name;
        if name_rva == 0 {
            break;
        }

        let nome = ler_cstr(base + name_rva as usize);
        if nome.to_ascii_lowercase() == alvo_dll {
            // Achamos a DLL. A INT (OriginalFirstThunk) da os nomes; a IAT
            // (FirstThunk) da os slots a trocar. Andam em paralelo.
            // SAFETY: leitura do union u.OriginalFirstThunk.
            let int_rva = unsafe { *d.u.OriginalFirstThunk() };
            let iat_rva = d.FirstThunk;
            if int_rva == 0 || iat_rva == 0 {
                return Err(format!("{} sem thunks utilizaveis", modulo));
            }

            let mut int = (base + int_rva as usize) as *const IMAGE_THUNK_DATA32;
            let mut iat = (base + iat_rva as usize) as *mut IMAGE_THUNK_DATA32;

            // Para diagnostico quando nao acha: o que ESTA importado.
            let mut vistos: Vec<String> = Vec::new();

            loop {
                // SAFETY: caminhamos INT e IAT em paralelo ate o thunk zerado.
                let int_val = unsafe { *(*int).u1.AddressOfData() };
                if int_val == 0 {
                    break;
                }

                // Importado por ordinal (bit alto setado) ou por nome. O cliente
                // hexed do RO costuma importar o Winsock por ORDINAL — foi
                // exatamente o que o log mostrou na primeira tentativa. Casamos
                // pelos dois: nome == func OU ordinal == `ordinal`.
                let por_ordinal = (int_val & IMAGE_ORDINAL_FLAG32) != 0;
                let bate = if por_ordinal {
                    let ord = (int_val & 0xFFFF) as u16;
                    if vistos.len() < 64 {
                        vistos.push(format!("#{}", ord));
                    }
                    ordinal != 0 && ord == ordinal
                } else {
                    let iby = (base + int_val as usize) as *const IMAGE_IMPORT_BY_NAME;
                    // O campo Name e um array flexivel a partir do offset 2.
                    let nome_func = ler_cstr((iby as usize) + 2);
                    let bate = nome_func == func;
                    if vistos.len() < 64 {
                        vistos.push(nome_func);
                    }
                    bate
                };

                if bate {
                    // Achamos o slot. Trocar sob VirtualProtect.
                    let slot = unsafe { (*iat).u1.Function_mut() } as *mut u32;
                    // SAFETY: slot aponta para o campo Function do thunk da IAT.
                    let original = unsafe { *slot } as usize;

                    let mut antiga: u32 = 0;
                    // SAFETY: slot valido; protegemos 4 bytes.
                    let ok = unsafe {
                        VirtualProtect(
                            slot as *mut _,
                            std::mem::size_of::<u32>(),
                            PAGE_READWRITE,
                            &mut antiga,
                        )
                    };
                    if ok == 0 {
                        let e = unsafe { GetLastError() };
                        return Err(format!("VirtualProtect falhou (erro {})", e));
                    }
                    // SAFETY: agora o slot e gravavel.
                    unsafe { *slot = novo as u32 };
                    // Restaura a protecao anterior.
                    let mut lixo: u32 = 0;
                    // SAFETY: mesma regiao.
                    unsafe {
                        VirtualProtect(
                            slot as *mut _,
                            std::mem::size_of::<u32>(),
                            antiga,
                            &mut lixo,
                        )
                    };
                    let como = if por_ordinal {
                        format!("ordinal {}", ordinal)
                    } else {
                        format!("nome {}", func)
                    };
                    log_dll(&format!("hook_iat: {} enganchado por {}", func, como));
                    return Ok(original);
                }

                // SAFETY: avanca um thunk (IMAGE_THUNK_DATA32 = 4 bytes em 32 bits).
                int = unsafe { int.add(1) };
                iat = unsafe { iat.add(1) };
            }
            // Nao achou. O log com o que ESTA importado transforma isto numa
            // linha de correcao (ajustar o ordinal) em vez de um misterio.
            log_dll(&format!(
                "hook_iat: {} nao tem {} (nome) nem #{} (ordinal). Importa: {}",
                modulo,
                func,
                ordinal,
                vistos.join(" ")
            ));
            return Err(format!(
                "{} nao importa {} por nome nem pelo ordinal {}",
                modulo, func, ordinal
            ));
        }

        // SAFETY: proximo descriptor.
        desc = unsafe { desc.add(1) };
    }

    Err(format!("o Ragexe nao importa {}", modulo))
}

/// Le uma string terminada em NUL de um endereco na propria imagem.
fn ler_cstr(addr: usize) -> String {
    let mut bytes = Vec::new();
    let mut p = addr as *const u8;
    // Teto de sanidade: nomes de DLL/funcao nao passam de algumas dezenas.
    for _ in 0..256 {
        // SAFETY: lendo bytes consecutivos de uma string da tabela de imports,
        // que a especificacao PE garante terminada em NUL.
        let b = unsafe { *p };
        if b == 0 {
            break;
        }
        bytes.push(b);
        // SAFETY: avanca um byte.
        p = unsafe { p.add(1) };
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Teto do `rse_watchdog.log`: 1 MB, o mesmo do log do Loader.
///
/// # Por que precisa de teto
///
/// O log abre em **append** — de propósito, para dois clientes na mesma pasta
/// não truncarem um ao outro. Sem rotação, porém, "append para sempre" é
/// literal: o arquivo só cresce, na pasta de quem joga todo dia.
///
/// Não é hipótese. Uma tarde de testes acumulou 2.199 linhas de 22 sessões, e
/// cada sessão hoje escreve mais do que antes: a linha de base da 6.4b sozinha
/// registra uma linha por dono de handle. Numa máquina movimentada isso passa
/// de 100 linhas por partida.
///
/// O log existe para responder "o que aconteceu na sessão que deu problema?" —
/// e para isso o último megabyte basta. Histórico de meses não serve a ninguém
/// e ocupa disco do jogador.
const LIMITE_LOG: u64 = 1_000_000;

/// Log proprio da DLL, num arquivo ao lado do jogo.
///
/// A DLL nao tem o arquivo de log do Loader. Este e o unico jeito de responder
/// "o hook disparou?" na maquina do jogador. Abre em modo append e nunca falha
/// de forma a atrapalhar o jogo: log e diagnostico, nao funcionalidade.
pub fn log_dll(msg: &str) {
    use std::io::Write;
    let caminho = caminho_do_log();

    // Rotação simples por tamanho, igual à do Loader. Se dois clientes fizerem
    // isto ao mesmo tempo, o pior caso é truncar duas vezes — mesmo resultado.
    if std::fs::metadata(&caminho)
        .map(|m| m.len() > LIMITE_LOG)
        .unwrap_or(false)
    {
        let _ = std::fs::write(&caminho, b"");
    }

    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&caminho) {
        let _ = writeln!(f, "[watchdog] {}", msg);
    }
}

/// `rse_watchdog.log` ao lado do executavel do jogo.
fn caminho_do_log() -> std::path::PathBuf {
    // O modulo do proprio processo e o Ragexe; o log fica na pasta dele.
    let mut buf = [0u16; 260];
    // SAFETY: NULL = modulo do processo; buf tem espaco para 260 wchars.
    let n = unsafe {
        winapi::um::libloaderapi::GetModuleFileNameW(ptr::null_mut(), buf.as_mut_ptr(), 260)
    };
    if n == 0 {
        return std::path::PathBuf::from("rse_watchdog.log");
    }
    let exe = String::from_utf16_lossy(&buf[..n as usize]);
    let mut p = std::path::PathBuf::from(exe);
    p.set_file_name("rse_watchdog.log");
    p
}

/// Le o blob de configuracao que o Loader escreveu na nossa memoria.
///
/// # SAFETY
///
/// `ptr` tem que apontar para uma regiao valida com pelo menos
/// `DLL_CONFIG_HEADER_LEN` bytes legiveis; o cabecalho diz o tamanho total, e so
/// entao lemos o resto. Quem chama e a `rse_configure`, e o ponteiro vem do
/// proprio Loader via `CreateRemoteThread` - nao ha caminho por onde um valor
/// arbitrario chegue aqui.
pub unsafe fn ler_config_da_memoria(ptr: *const u8) -> Result<Vec<u8>, String> {
    use rse_protocol::dll_config::DLL_CONFIG_HEADER_LEN;

    if ptr.is_null() {
        return Err("ponteiro de configuracao nulo".to_string());
    }
    // Primeiro o cabecalho, para saber o tamanho do nome do pipe.
    let mut cabecalho = [0u8; DLL_CONFIG_HEADER_LEN];
    // SAFETY: contrato da funcao garante DLL_CONFIG_HEADER_LEN bytes legiveis.
    ptr::copy_nonoverlapping(ptr, cabecalho.as_mut_ptr(), DLL_CONFIG_HEADER_LEN);

    // O byte 5 e o tamanho do nome do pipe (ver dll_config).
    let tam_pipe = cabecalho[5] as usize;
    let total = DLL_CONFIG_HEADER_LEN + tam_pipe;

    let mut blob = vec![0u8; total];
    // SAFETY: o Loader escreveu `total` bytes contiguos; tam_pipe vem do proprio
    // cabecalho que ele montou.
    ptr::copy_nonoverlapping(ptr, blob.as_mut_ptr(), total);
    Ok(blob)
}
