//! Detecções da Fase 6 — o que só se enxerga de dentro do processo.
//!
//! # Depurador anexado (`3001 DEBUGGER_ATTACHED`)
//!
//! Um depurador ligado ao cliente é a ferramenta de quem está **fazendo
//! engenharia reversa ao vivo**: achando o endereço do HP na memória, seguindo o
//! caminho de um packet, procurando onde fica a checagem de delay. Não é o
//! cheater final — é quem **fabrica** o cheat.
//!
//! # 🚨 O que esta detecção vale, com honestidade
//!
//! Anti-debug é uma **corrida armamentista que o defensor não ganha**. Existem
//! ferramentas prontas (ScyllaHide, TitanHide e afins) cuja única função é
//! esconder o depurador de exatamente estas verificações, e um driver de kernel
//! esconde de todas elas. Quem sabe o que está fazendo passa.
//!
//! Então o que isto pega, de verdade: **o sujeito casual** que abre o cliente no
//! x64dbg/Cheat Engine sem se proteger. Que é a maioria de quem tenta, e é
//! informação que hoje você não tem nenhuma.
//!
//! O valor real não é bloquear — é **saber**. Uma conta que aparece com
//! depurador anexado três vezes numa semana é um sinal que vale investigar,
//! muito antes de o cheat pronto aparecer em campo.
//!
//! # Por que quatro checagens, e não uma
//!
//! Elas medem a mesma coisa em **camadas diferentes** do sistema:
//!
//! | # | Como | Camada |
//! |---|---|---|
//! | A | `IsDebuggerPresent` | API do kernel32 |
//! | B | `CheckRemoteDebuggerPresent` | API do kernel32 |
//! | C | `NtQueryInformationProcess(ProcessDebugPort)` | ntdll, mais fundo |
//! | D | `NtQueryInformationProcess(ProcessDebugObjectHandle)` | ntdll, outro campo |
//!
//! Isso dá algo que uma checagem sozinha não daria: **quando elas discordam,
//! a discordância é a informação**. Se a API do kernel32 diz "sem depurador" mas
//! o ntdll diz que há, alguém enganchou a API para esconder — e isso é um
//! indício *mais forte* do que o depurador em si, porque revela intenção.
//! Ninguém engancha `IsDebuggerPresent` por acidente.

#![cfg(windows)]

use crate::sys;

/// `3001 DEBUGGER_ATTACHED` — severidade crítica no RSE_SPEC §9.
const COD_DEBUGGER: u16 = 3001;
/// Faixa experimental (6000–6999): a API mentiu em relação ao ntdll.
const COD_API_MENTIU: u16 = 6010;

/// O que uma varredura encontrou.
#[derive(Default, PartialEq, Eq, Clone, Copy)]
pub struct Achados {
    pub depurador: bool,
    pub api_mentiu: bool,
}

impl Achados {
    pub fn limpo(&self) -> bool {
        !self.depurador && !self.api_mentiu
    }
}

/// Roda as quatro checagens e resume o que viu.
pub fn procurar_depurador() -> Achados {
    let a = por_api_simples();
    let b = por_api_remota();
    let c = por_ntdll(PROCESS_DEBUG_PORT);
    let d = por_ntdll(PROCESS_DEBUG_OBJECT_HANDLE);

    let camada_api = a || b;
    let camada_ntdll = c.unwrap_or(false) || d.unwrap_or(false);

    Achados {
        depurador: camada_api || camada_ntdll,
        // Só acusa a mentira quando o ntdll REALMENTE respondeu (não `None`):
        // uma consulta que falhou não é prova de nada, e acusar em cima de erro
        // de API viraria falso-positivo em máquina com política esquisita.
        api_mentiu: camada_ntdll && !camada_api,
    }
}

/// Traduz os achados em linhas de `REPORT` (`code|severity|detail`).
pub fn linhas_de_report(a: &Achados) -> Vec<String> {
    let mut v = Vec::new();
    if a.depurador {
        v.push(format!(
            "{}|critica|depurador anexado ao cliente",
            COD_DEBUGGER
        ));
    }
    if a.api_mentiu {
        v.push(format!(
            "{}|alta|IsDebuggerPresent nega o que o ntdll confirma — API enganchada para esconder depurador",
            COD_API_MENTIU
        ));
    }
    v
}

// ===========================================================================
//  As quatro checagens
// ===========================================================================

fn por_api_simples() -> bool {
    // SAFETY: sem parâmetros, sem como falhar.
    unsafe { winapi::um::debugapi::IsDebuggerPresent() != 0 }
}

/// Pega depurador anexado **de outro processo** — o caso comum: o jogo abre
/// normal e o sujeito anexa o x64dbg depois.
fn por_api_remota() -> bool {
    use winapi::um::debugapi::CheckRemoteDebuggerPresent;
    use winapi::um::processthreadsapi::GetCurrentProcess;

    let mut presente: i32 = 0;
    // SAFETY: pseudo-handle do próprio processo; `presente` é um i32 válido.
    let ok = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut presente) };
    ok != 0 && presente != 0
}

const PROCESS_DEBUG_PORT: u32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;

/// Consulta o ntdll direto, abaixo da camada que o kernel32 expõe.
///
/// `None` = a consulta não pôde ser feita (ntdll não resolveu, ou o campo não
/// existe nesta versão do Windows). `None` **não** é "sem depurador": é "não
/// sei", e a diferença importa para não acusar ninguém em cima de erro de API.
fn por_ntdll(classe: u32) -> Option<bool> {
    use winapi::ctypes::c_void;
    use winapi::um::processthreadsapi::GetCurrentProcess;

    type NtQueryInformationProcess = unsafe extern "system" fn(
        *mut c_void, // ProcessHandle
        u32,         // ProcessInformationClass
        *mut c_void, // ProcessInformation
        u32,         // ProcessInformationLength
        *mut u32,    // ReturnLength
    ) -> i32;

    let endereco = sys::endereco_de("ntdll.dll", "NtQueryInformationProcess")?;
    // SAFETY: o símbolo veio de GetProcAddress no ntdll e tem esta assinatura,
    // que é estável desde o Windows XP.
    let f: NtQueryInformationProcess = unsafe { std::mem::transmute(endereco) };

    let mut valor: usize = 0;
    let mut devolvido: u32 = 0;
    // SAFETY: `valor` tem o tamanho declarado; handle do próprio processo.
    let status = unsafe {
        f(
            GetCurrentProcess() as *mut c_void,
            classe,
            &mut valor as *mut usize as *mut c_void,
            std::mem::size_of::<usize>() as u32,
            &mut devolvido,
        )
    };

    if status != 0 {
        return None; // não sei
    }
    Some(valor != 0)
}
