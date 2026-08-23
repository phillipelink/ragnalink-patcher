//! `rse-testpatch` — remenda **um byte** do código do jogo, para exercitar a
//! detecção `3002` da Fase 6.5.
//!
//! ```text
//! cargo run -p rse-testpatch            # remenda por 90 s e desfaz
//! cargo run -p rse-testpatch -- 45      # por 45 s
//! ```
//!
//! # O que esta ferramenta prova
//!
//! A 6.4b pergunta *quem pode escrever* na memória do jogo, e por isso depende
//! de conseguir abrir o processo do suspeito — o que falha contra cheat
//! elevado. A 6.5 pergunta *o que foi escrito*, e para isso não precisa de
//! ninguém: é a nossa própria memória.
//!
//! Esta ferramenta escreve **um único byte** dentro da seção de código do
//! Ragexe e o devolve ao original no fim. Se a 6.5 estiver funcionando, esse um
//! byte é suficiente para acender `3002` — e é a diferença entre uma detecção
//! que enxerga o efeito e uma que só enxerga o autor.
//!
//! # 🚨 Por que remendar dentro de uma área de preenchimento, e não em código real
//!
//! O alinhamento entre funções de um binário compilado é preenchido com `0xCC`
//! (`int3`) ou `0x90` (`nop`) — bytes que **nunca são executados**, porque estão
//! entre o fim de uma função e o começo da próxima.
//!
//! Escrever ali produz exatamente o mesmo efeito para a detecção (a seção de
//! código mudou) sem nenhum risco de derrubar o jogo. Remendar uma instrução de
//! verdade provaria a mesma coisa e poderia travar o cliente no meio do teste —
//! e uma ferramenta de teste que quebra o alvo é uma ferramenta que ninguém
//! roda duas vezes.
//!
//! A ferramenta **restaura** o byte no fim. Se ela morrer no meio, feche e
//! reabra o jogo: o código vem limpo do disco a cada abertura.

fn main() {
    #[cfg(not(windows))]
    {
        eprintln!("esta ferramenta so faz sentido no Windows");
        std::process::exit(2);
    }
    #[cfg(windows)]
    win::executar();
}

#[cfg(windows)]
mod win {
    use std::time::Duration;

    use winapi::shared::minwindef::{FALSE, MAX_PATH};
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::memoryapi::{ReadProcessMemory, VirtualProtectEx, WriteProcessMemory};
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Module32FirstW, Process32FirstW, Process32NextW, MODULEENTRY32W,
        PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
    };
    use winapi::um::winnt::{
        HANDLE, PAGE_EXECUTE_READWRITE, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    const ALVO: &str = "RagnaLinK_ptBR5.exe";
    /// Quantos bytes varrer procurando preenchimento entre funções.
    const JANELA_BUSCA: usize = 512 * 1024;
    /// Quantos `0xCC`/`0x90` seguidos convencem que ali é preenchimento.
    const SEGUIDOS: usize = 8;

    pub fn executar() {
        let segundos: u64 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(90);

        let pid = match achar_pid(ALVO) {
            Some(p) => p,
            None => {
                eprintln!("nao achei {}. Abra o jogo pelo launcher primeiro.", ALVO);
                std::process::exit(1);
            }
        };
        let base = match base_do_modulo(pid, ALVO) {
            Some(b) => b,
            None => {
                eprintln!("nao achei a base do modulo do jogo");
                std::process::exit(1);
            }
        };

        // SAFETY: abrir o alvo para leitura/escrita; handle fechado no fim.
        let h = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                FALSE,
                pid,
            )
        };
        if h.is_null() {
            // SAFETY: chamada logo apos a falha, na mesma thread.
            eprintln!("OpenProcess falhou (erro {})", unsafe { GetLastError() });
            std::process::exit(1);
        }

        let (inicio, tam) = match secao_de_codigo(h, base) {
            Some(x) => x,
            None => {
                // SAFETY: handle valido.
                unsafe { CloseHandle(h) };
                eprintln!("nao achei a secao de codigo no PE do alvo");
                std::process::exit(1);
            }
        };
        println!("alvo: {} (pid {})", ALVO, pid);
        println!("secao de codigo: 0x{:x} .. 0x{:x} ({} bytes)", inicio, inicio + tam, tam);

        let endereco = match achar_preenchimento(h, inicio, tam) {
            Some(e) => e,
            None => {
                // SAFETY: handle valido.
                unsafe { CloseHandle(h) };
                eprintln!("nao achei area de preenchimento; abortando em vez de remendar codigo real");
                std::process::exit(1);
            }
        };

        let original = match ler_byte(h, endereco) {
            Some(b) => b,
            None => {
                // SAFETY: handle valido.
                unsafe { CloseHandle(h) };
                eprintln!("nao consegui ler o byte original");
                std::process::exit(1);
            }
        };
        // Troca 0xCC por 0x90 (ou o contrario) — os dois sao preenchimento.
        let novo = if original == 0x90 { 0xCC } else { 0x90 };

        if !escrever_byte(h, endereco, novo) {
            // SAFETY: handle valido.
            unsafe { CloseHandle(h) };
            // SAFETY: chamada logo apos a falha.
            eprintln!("nao consegui escrever (erro {})", unsafe { GetLastError() });
            std::process::exit(1);
        }

        println!();
        println!("  remendei UM byte em 0x{:x}: 0x{:02X} -> 0x{:02X}", endereco, original, novo);
        println!("  (area de preenchimento entre funcoes — nao e executada)");
        println!();
        println!("  A 6.4b nao ve nada disto: ela olha QUEM abriu handle.");
        println!("  A 6.5 ve, porque olha O QUE mudou na propria memoria.");
        println!();
        println!("  Esperado no servidor, em ate 60 s:");
        println!("    RSE: violacao 3002 sev=critica detalhe=codigo alterado em memoria: codigo do jogo");
        println!();
        println!("segurando por {} s...", segundos);

        std::thread::sleep(Duration::from_secs(segundos));

        if escrever_byte(h, endereco, original) {
            println!("byte restaurado. O 3002 para de aparecer no proximo relatorio.");
        } else {
            println!("NAO consegui restaurar o byte. Feche e reabra o jogo — o codigo");
            println!("vem limpo do disco a cada abertura.");
        }
        // SAFETY: handle valido que abrimos acima.
        unsafe { CloseHandle(h) };
    }

    // -- leitura/escrita ----------------------------------------------------

    fn ler(h: HANDLE, endereco: usize, quanto: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; quanto];
        let mut lidos = 0usize;
        // SAFETY: h valido; buf tem `quanto` bytes.
        let ok = unsafe {
            ReadProcessMemory(
                h,
                endereco as *const winapi::ctypes::c_void,
                buf.as_mut_ptr() as *mut winapi::ctypes::c_void,
                quanto,
                &mut lidos,
            )
        };
        if ok == 0 || lidos == 0 {
            return None;
        }
        buf.truncate(lidos);
        Some(buf)
    }

    fn ler_byte(h: HANDLE, endereco: usize) -> Option<u8> {
        ler(h, endereco, 1).map(|v| v[0])
    }

    /// Escreve um byte, abrindo a proteção da página e devolvendo-a depois.
    ///
    /// Página de código é somente-execução/leitura; escrever exige
    /// `VirtualProtectEx` antes. Restaurar a proteção original é o que impede a
    /// ferramenta de deixar o processo num estado que ela mesma criou.
    fn escrever_byte(h: HANDLE, endereco: usize, valor: u8) -> bool {
        let mut antiga: u32 = 0;
        // SAFETY: h valido; muda a protecao de uma pagina do alvo.
        let ok = unsafe {
            VirtualProtectEx(
                h,
                endereco as *mut winapi::ctypes::c_void,
                1,
                PAGE_EXECUTE_READWRITE,
                &mut antiga,
            )
        };
        if ok == 0 {
            return false;
        }

        let b = [valor];
        let mut escritos = 0usize;
        // SAFETY: h valido; um byte a partir de um ponteiro valido.
        let escreveu = unsafe {
            WriteProcessMemory(
                h,
                endereco as *mut winapi::ctypes::c_void,
                b.as_ptr() as *const winapi::ctypes::c_void,
                1,
                &mut escritos,
            )
        };

        let mut lixo: u32 = 0;
        // SAFETY: devolve a protecao original; falha aqui nao invalida a escrita.
        unsafe {
            VirtualProtectEx(
                h,
                endereco as *mut winapi::ctypes::c_void,
                1,
                antiga,
                &mut lixo,
            )
        };
        escreveu != 0 && escritos == 1
    }

    /// Procura uma sequência de preenchimento entre funções.
    fn achar_preenchimento(h: HANDLE, inicio: usize, tam: usize) -> Option<usize> {
        let quanto = tam.min(JANELA_BUSCA);
        // Começa depois do início da seção: as primeiras funções costumam ser
        // densas, e o preenchimento aparece mais adiante.
        let bloco = ler(h, inicio + quanto / 4, quanto)?;
        let mut corrida = 0usize;
        for (i, b) in bloco.iter().enumerate() {
            if *b == 0xCC || *b == 0x90 {
                corrida += 1;
                if corrida >= SEGUIDOS {
                    // O meio da corrida, longe das bordas.
                    return Some(inicio + quanto / 4 + i - corrida / 2);
                }
            } else {
                corrida = 0;
            }
        }
        None
    }

    // -- travessia do PE no processo alvo -----------------------------------

    fn secao_de_codigo(h: HANDLE, base: usize) -> Option<(usize, usize)> {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        let cab = ler(h, base, 0x400)?;
        if cab.len() < 0x40 || cab[0] != b'M' || cab[1] != b'Z' {
            return None;
        }
        let lfanew = u32::from_le_bytes([cab[0x3C], cab[0x3D], cab[0x3E], cab[0x3F]]) as usize;
        if lfanew < 0x40 || lfanew + 0x18 > cab.len() {
            return None;
        }
        if &cab[lfanew..lfanew + 4] != b"PE\0\0" {
            return None;
        }
        let fh = lfanew + 4;
        let num = u16::from_le_bytes([cab[fh + 2], cab[fh + 3]]) as usize;
        let tam_opt = u16::from_le_bytes([cab[fh + 16], cab[fh + 17]]) as usize;
        let secoes = fh + 20 + tam_opt;

        let tabela = ler(h, base + secoes, num * 40)?;
        for i in 0..num {
            let s = i * 40;
            if s + 40 > tabela.len() {
                break;
            }
            let carac = u32::from_le_bytes([tabela[s + 36], tabela[s + 37], tabela[s + 38], tabela[s + 39]]);
            if carac & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            let vtam = u32::from_le_bytes([tabela[s + 8], tabela[s + 9], tabela[s + 10], tabela[s + 11]]) as usize;
            let rva = u32::from_le_bytes([tabela[s + 12], tabela[s + 13], tabela[s + 14], tabela[s + 15]]) as usize;
            if rva == 0 || vtam == 0 {
                continue;
            }
            return Some((base + rva, vtam));
        }
        None
    }

    // -- descoberta de processo e módulo ------------------------------------

    fn achar_pid(nome: &str) -> Option<u32> {
        // SAFETY: snapshot de processos; handle fechado abaixo.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: POD; dwSize obrigatorio.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut achado = None;
        // SAFETY: snap valido.
        unsafe {
            if Process32FirstW(snap, &mut e) != 0 {
                loop {
                    let fim = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
                    if String::from_utf16_lossy(&e.szExeFile[..fim]).eq_ignore_ascii_case(nome) {
                        achado = Some(e.th32ProcessID);
                        break;
                    }
                    if Process32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        achado
    }

    fn base_do_modulo(pid: u32, _nome: &str) -> Option<usize> {
        // SAFETY: snapshot de modulos do alvo; TH32CS_SNAPMODULE32 e o que
        // permite a um processo 64 bits enxergar modulos de um alvo 32 bits.
        let snap =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: POD; dwSize obrigatorio.
        let mut m: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        m.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        // SAFETY: snap valido. O PRIMEIRO modulo do snapshot e sempre o proprio
        // executavel do processo — e por isso nao precisamos casar pelo nome.
        let r = unsafe {
            let ok = Module32FirstW(snap, &mut m);
            CloseHandle(snap);
            if ok != 0 {
                Some(m.modBaseAddr as usize)
            } else {
                None
            }
        };
        r
    }
}
