//! `rse-whoholds` — lista quem segura handle de processo para um PID.
//!
//! ```text
//! cargo run -p rse-whoholds --target i686-pc-windows-msvc   -- <pid>
//! cargo run -p rse-whoholds --target x86_64-pc-windows-msvc -- <pid>
//! ```
//!
//! # Por que esta ferramenta existe
//!
//! A Fase 6.4b, rodando **dentro** do Ragexe (32 bits, sob WOW64), passou a
//! reportar coisas implausíveis: `git.exe`, `cargo.exe` e `conhost.exe`
//! segurando `PROCESS_ALL_ACCESS` no cliente do jogo. Nenhum desses programas
//! abre o Ragnarok.
//!
//! O problema: não dá para saber se a lista está errada sem uma segunda opinião.
//! Esta ferramenta é essa segunda opinião — **o mesmo algoritmo**, compilável
//! nas duas arquiteturas:
//!
//! * em **x86_64** ela roda nativa, sem WOW64 no meio;
//! * em **i686** ela passa exatamente pela mesma travessia que a DLL.
//!
//! Rodar as duas contra o mesmo PID e comparar responde a pergunta de forma
//! decisiva:
//!
//! | 64 bits | 32 bits | Conclusão |
//! |---|---|---|
//! | lista curta e plausível | lista longa | a leitura em WOW64 ainda está errada |
//! | as duas iguais | | os donos são reais, e a surpresa é minha |
//!
//! Sem este experimento, qualquer conserto seria chute — e chute em cima de
//! detecção que acusa gente é exatamente o que não se pode fazer.

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
    use std::collections::BTreeMap;

    use winapi::ctypes::c_void;
    use winapi::shared::minwindef::MAX_PATH;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use winapi::um::processthreadsapi::OpenProcess;
    use super::dup::alvo_do_handle;
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = -1_073_741_820;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[derive(Clone, Copy, PartialEq)]
    enum Largura {
        B32,
        B64,
    }
    impl Largura {
        fn cabecalho(self) -> usize {
            if self == Largura::B32 {
                8
            } else {
                16
            }
        }
        fn passo(self) -> usize {
            if self == Largura::B32 {
                28
            } else {
                40
            }
        }
        fn nome(self) -> &'static str {
            if self == Largura::B32 {
                "32"
            } else {
                "64"
            }
        }
    }

    struct Entrada {
        objeto: u64,
        dono_pid: u64,
        valor_handle: u64,
        acesso: u32,
        tipo: u16,
    }

    unsafe fn ler(p: *const u8, l: Largura) -> Entrada {
        match l {
            Largura::B32 => Entrada {
                objeto: (p as *const u32).read_unaligned() as u64,
                dono_pid: (p.add(4) as *const u32).read_unaligned() as u64,
                valor_handle: (p.add(8) as *const u32).read_unaligned() as u64,
                acesso: (p.add(12) as *const u32).read_unaligned(),
                tipo: (p.add(18) as *const u16).read_unaligned(),
            },
            Largura::B64 => Entrada {
                objeto: (p as *const u64).read_unaligned(),
                dono_pid: (p.add(8) as *const u64).read_unaligned(),
                valor_handle: (p.add(16) as *const u64).read_unaligned(),
                acesso: (p.add(24) as *const u32).read_unaligned(),
                tipo: (p.add(30) as *const u16).read_unaligned(),
            },
        }
    }

    unsafe fn total(base: *const u8, l: Largura) -> u64 {
        match l {
            Largura::B32 => (base as *const u32).read_unaligned() as u64,
            Largura::B64 => (base as *const u64).read_unaligned(),
        }
    }

    type NtQSI = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

    pub fn executar() {
        let alvo: u32 = match std::env::args().nth(1).and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => {
                eprintln!("uso: rse-whoholds <pid>");
                eprintln!("     (o PID do RagnaLinK_ptBR5.exe, com o jogo aberto)");
                std::process::exit(2);
            }
        };

        println!(
            "compilado para {} bits",
            if cfg!(target_pointer_width = "64") {
                "64"
            } else {
                "32"
            }
        );

        let mapa = mapa_pid_nome();

        // ORDEM: abrir o handle ANTES de fotografar a tabela — o retrato não
        // contém um handle criado depois dele.
        // SAFETY: abrir processo alheio para consulta; handle fechado no fim.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, alvo) };
        if h.is_null() {
            eprintln!("nao consegui abrir o pid {} (rode como o mesmo usuario)", alvo);
            std::process::exit(1);
        }
        let valor = h as u64;

        let mut buf: Vec<usize> = vec![0usize; 512 * 1024];
        let bytes = match carregar(&mut buf) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        };
        let base = buf.as_ptr() as *const u8;

        let vivos: std::collections::BTreeSet<u32> = mapa.keys().copied().collect();
        let c32 = unsafe { confianca(base, bytes, Largura::B32, &vivos) };
        let c64 = unsafe { confianca(base, bytes, Largura::B64, &vivos) };
        let larg = if c64 > c32 { Largura::B64 } else { Largura::B32 };
        println!(
            "confianca 32b={:.2}  64b={:.2}  -> lendo em {} bits",
            c32,
            c64,
            larg.nome()
        );

        let cabem = bytes.saturating_sub(larg.cabecalho()) / larg.passo();
        let n = (unsafe { total(base, larg) }).min(cabem as u64) as usize;

        // Âncora.
        let mut ancora: Option<(u64, u16)> = None;
        let mut minhas = 0usize;
        for i in 0..n {
            let e = unsafe { ler(base.add(larg.cabecalho() + i * larg.passo()), larg) };
            if e.dono_pid != std::process::id() as u64 {
                continue;
            }
            minhas += 1;
            if e.valor_handle == valor {
                ancora = Some((e.objeto, e.tipo));
            }
        }
        // SAFETY: handle valido.
        unsafe { CloseHandle(h) };

        let (obj, tipo) = match ancora {
            Some(a) => a,
            None => {
                eprintln!(
                    "nao achei o meu handle (0x{:x}) entre as {} entradas minhas de {}",
                    valor, minhas, n
                );
                std::process::exit(1);
            }
        };
        println!(
            "{} entradas na tabela; ancora objeto=0x{:x} tipo={}",
            n, obj, tipo
        );
        println!();

        if obj == 0 {
            println!("!! ponteiro de objeto REDIGIDO (0) — o Windows zera isto para");
            println!("   quem chama sem elevacao. Comparar ponteiro casaria com TUDO.");
            println!("   Confirmando cada candidato por duplicacao de handle...");
            println!();
        }

        let mut donos: BTreeMap<u32, (String, u32)> = BTreeMap::new();
        let mut sem_resposta = 0usize;
        let mut candidatos = 0usize;
        for i in 0..n {
            let e = unsafe { ler(base.add(larg.cabecalho() + i * larg.passo()), larg) };
            if e.tipo != tipo {
                continue;
            }
            if obj != 0 && e.objeto != obj {
                continue;
            }
            let pid = e.dono_pid as u32;
            if pid == std::process::id() {
                continue;
            }
            // Com ponteiro redigido, o unico jeito honesto de saber o alvo do
            // handle e perguntar ao proprio Windows.
            if obj == 0 {
                candidatos += 1;
                match alvo_do_handle(pid, e.valor_handle) {
                    Some(a) if a == alvo => {}
                    Some(_) => continue,
                    None => {
                        sem_resposta += 1;
                        continue;
                    }
                }
            }
            let nome = mapa
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| format!("<pid {} sem nome>", pid));
            donos.entry(pid).or_insert((nome, e.acesso));
        }

        if obj == 0 {
            println!(
                "{} candidato(s) examinados, {} sem permissao para duplicar",
                candidatos, sem_resposta
            );
        }
        println!("{} processo(s) seguram handle para o pid {}:", donos.len(), alvo);
        for (pid, (nome, acesso)) in &donos {
            println!("   {:>7}  0x{:06x}  {}", pid, acesso, nome);
        }
    }

    unsafe fn confianca(
        base: *const u8,
        bytes: usize,
        l: Largura,
        vivos: &std::collections::BTreeSet<u32>,
    ) -> f32 {
        let cabem = bytes.saturating_sub(l.cabecalho()) / l.passo();
        let n = total(base, l).min(cabem as u64) as usize;
        if n == 0 {
            return 0.0;
        }
        let passo = (n / 2000).max(1);
        let (mut olhadas, mut batem) = (0usize, 0usize);
        let mut i = 0;
        while i < n {
            let e = ler(base.add(l.cabecalho() + i * l.passo()), l);
            olhadas += 1;
            if e.dono_pid <= u32::MAX as u64 && vivos.contains(&(e.dono_pid as u32)) {
                batem += 1;
            }
            i += passo;
        }
        batem as f32 / olhadas.max(1) as f32
    }

    fn carregar(buf: &mut Vec<usize>) -> Result<usize, String> {
        // SAFETY: ntdll sempre carregada; simbolo estavel.
        let f: NtQSI = unsafe {
            let m = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
            let p = GetProcAddress(m, b"NtQuerySystemInformation\0".as_ptr() as *const i8);
            if p.is_null() {
                return Err("NtQuerySystemInformation nao resolveu".into());
            }
            std::mem::transmute(p)
        };
        loop {
            let bytes = buf.len() * std::mem::size_of::<usize>();
            let mut dev: u32 = 0;
            // SAFETY: buffer com `bytes` validos.
            let st = unsafe {
                f(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buf.as_mut_ptr() as *mut c_void,
                    bytes as u32,
                    &mut dev,
                )
            };
            if st == 0 {
                return Ok(bytes);
            }
            if st != STATUS_INFO_LENGTH_MISMATCH {
                return Err(format!("NtQuerySystemInformation devolveu 0x{:x}", st));
            }
            let novo = (bytes * 2).max(dev as usize + 64 * 1024);
            if novo > 96 * 1024 * 1024 {
                return Err("tabela acima do teto".into());
            }
            buf.resize(novo / std::mem::size_of::<usize>() + 1, 0usize);
        }
    }

    fn mapa_pid_nome() -> BTreeMap<u32, String> {
        let mut m = BTreeMap::new();
        // SAFETY: snapshot de processos; handle fechado abaixo.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return m;
        }
        // SAFETY: POD; dwSize obrigatorio.
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: snap valido.
        unsafe {
            if Process32FirstW(snap, &mut e) != 0 {
                loop {
                    let fim = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
                    m.insert(
                        e.th32ProcessID,
                        String::from_utf16_lossy(&e.szExeFile[..fim]),
                    );
                    if Process32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        m
    }
}

#[cfg(windows)]
mod dup {
    use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
    use winapi::um::processthreadsapi::{GetCurrentProcess, GetProcessId, OpenProcess};
    use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, HANDLE};

    const PROCESS_DUP_HANDLE: u32 = 0x0040;

    /// Para qual PID aponta o handle `valor` do processo `dono`?
    ///
    /// `None` = nao consegui perguntar (sem permissao sobre o dono). Nunca chuta.
    pub fn alvo_do_handle(dono: u32, valor: u64) -> Option<u32> {
        // SAFETY: abrir processo alheio so para duplicar; fechado abaixo.
        let origem = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, dono) };
        if origem.is_null() {
            return None;
        }
        let mut copia: HANDLE = std::ptr::null_mut();
        // SAFETY: origem valido; valor veio da tabela como handle daquele processo.
        let ok = unsafe {
            DuplicateHandle(
                origem,
                valor as HANDLE,
                GetCurrentProcess(),
                &mut copia,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        // SAFETY: handles validos.
        let r = if ok != 0 && !copia.is_null() {
            let id = unsafe { GetProcessId(copia) };
            unsafe { CloseHandle(copia) };
            Some(id)
        } else {
            None
        };
        // SAFETY: handle do dono.
        unsafe { CloseHandle(origem) };
        r
    }
}
