//! Fase 6.4b — **quem tem a mão dentro do cliente** (`3003`).
//!
//! # O buraco que este arquivo fecha
//!
//! A 6.4 (`processos.rs`) procura *nomes* de ferramentas conhecidas. O teto dela
//! é óbvio e está escrito lá: renomear `cheatengine-x86_64.exe` para
//! `svchost32.exe` passa por ela inteira. E não é hipótese — existe gente
//! **vendendo** Cheat Engine recompilado e renomeado exatamente com essa
//! promessa, "indetectável".
//!
//! A saída não é uma lista maior. É parar de olhar o nome.
//!
//! # O que um editor de memória não pode dispensar
//!
//! Para ler ou escrever na memória de outro processo no Windows, existe **um**
//! caminho em modo usuário: obter um `HANDLE` para aquele processo com direito
//! de acesso suficiente, e então usar `WriteProcessMemory`, `VirtualProtectEx`
//! ou `CreateRemoteThread` sobre ele.
//!
//! Esse handle é **visível para o sistema inteiro**. Não importa como o programa
//! se chama, quem o compilou, se limpou a tabela de importação ou se chamou a
//! API por syscall direta: o objeto existe na tabela do kernel, e ele aponta
//! para nós.
//!
//! A pergunta deste módulo é, então: **quem, além do nosso Loader, tem um handle
//! para este processo com direito de escrita?**
//!
//! Renomear não ajuda. Recompilar não ajuda. Escrever do zero não ajuda — porque
//! não estamos olhando uma assinatura do programa, e sim o rastro daquilo que
//! ele precisa fazer para funcionar.
//!
//! # O truque que faz isto rodar sem privilégio nenhum
//!
//! `NtQuerySystemInformation(SystemExtendedHandleInformation)` devolve **todos**
//! os handles de **todos** os processos. Cada entrada traz o PID do dono, o
//! valor do handle, a máscara de acesso — e o **ponteiro do objeto de kernel**.
//!
//! O caminho ingênuo daqui seria duplicar cada handle de processo para dentro de
//! nós e perguntar `GetProcessId()`. Isso exige `PROCESS_DUP_HANDLE` sobre o
//! dono — que falha justamente contra quem interessa — e é lento: uma syscall
//! por handle, em dezenas de milhares deles.
//!
//! O caminho barato: **abrimos um handle para nós mesmos**, achamos a nossa
//! própria entrada na tabela e lemos o ponteiro de objeto dela. A partir daí,
//! qualquer entrada com o mesmo ponteiro aponta para o nosso processo.
//!
//! **Só que esse caminho nem sempre existe.** O Windows zera os ponteiros de
//! kernel desta tabela para quem chama sem elevação — e o nosso Loader roda
//! `asInvoker` de propósito, desde que tiramos o UAC. Quando isso acontece, a
//! âncora vem `0`, `objeto == ancora` vira `0 == 0`, e o filtro casa com tudo.
//!
//! Foi exatamente o que aconteceu, e o resultado enganou por um bom tempo: a
//! varredura listava **145 processos** — `git.exe`, `conhost.exe`, `cargo.exe` —
//! todos reais, todos com máscara real, e nenhum deles com handle para o jogo.
//! Estávamos respondendo "quem tem handle para *qualquer* processo?".
//!
//! Por isso hoje há dois caminhos: se o ponteiro veio, compara ponteiro; se veio
//! zerado, **pergunta ao Windows** — duplica o handle e confere `GetProcessId`.
//! Mais caro, e correto onde o barato mente.
//!
//! # 🚨 Duas armadilhas que este arquivo já caiu, para ninguém cair de novo
//!
//! **1. A ordem importa.** Abrir o handle *depois* de fotografar a tabela é
//! garantia de falha: o retrato não contém um handle que ainda não existia.
//! Abre-se primeiro, fotografa-se depois.
//!
//! **2. A largura da tabela não é a do processo.** A primeira versão declarava
//! a entrada com `usize` e supunha que um processo 32 bits receberia a tabela em
//! 32 bits. O Ragexe roda sob **WOW64** num Windows 64 bits, e a tabela é
//! estrutura do kernel. Lendo campos de 8 bytes como se fossem de 4, a
//! varredura passou a acusar **processos inocentes** — `ssh.exe`, `cargo.exe`,
//! `chrome.exe` — apresentando handles de *arquivo* e de *evento* como se
//! fossem de processo. Hoje a largura é **detectada e validada** (ver
//! `Largura` e `confianca`), e a varredura **recusa relatar** se não confiar na
//! leitura.
//!
//! Da segunda armadilha saiu também o filtro por `ObjectTypeIndex`, que a
//! primeira versão dispensou por escrito com o argumento de que casar o
//! ponteiro do objeto já garantiria o tipo. O argumento só vale se a âncora for
//! mesmo um processo — e quando a leitura sai torta, não é. O índice do tipo
//! muda entre versões do Windows, então não o comparamos com constante alguma:
//! comparamos com o tipo da **nossa própria âncora**.
//!
//! # 🚨 Falso-positivo aqui é a regra, e um deles é garantido
//!
//! Quem legitimamente segura um handle com escrita no cliente:
//!
//! * **o nosso próprio Loader** — ele criou o processo suspenso e injetou esta
//!   DLL; tem `PROCESS_ALL_ACCESS`. Acende em 100% das sessões;
//! * o **`csrss.exe`** da sessão, que mantém handle para todo processo dela;
//! * antivírus e EDR, overlays (Discord, Steam, MSI Afterburner, RivaTuner),
//!   OBS com captura de jogo, o próprio Gerenciador de Tarefas aberto.
//!
//! Duas decisões saem disso:
//!
//! 1. **O Loader é excluído pelo PPID**, não pelo nome. O PID do pai vem do
//!    `ProcessBasicInformation` — e um cheat não consegue se passar por ele
//!    enquanto o Loader estiver vivo, que é a sessão inteira. Excluir por nome
//!    seria um convite: bastaria o cheat se chamar `rse_loader.exe`.
//! 2. **Nada mais é silenciado.** O que é esperado sai como `6030` informativo
//!    em vez de alerta — mas **sai**. A diferença entre "não reportado" e
//!    "reportado em outro nível" é a diferença entre esconder e organizar, e só
//!    a segunda deixa o operador julgar.
//!
//! # A linha de base, e por que ela era obrigatória
//!
//! Na estreia desta fase, uma máquina limpa devolveu **95 donos** numa
//! varredura: svchost, conhost, chrome, msedgewebview2, Riot Client, EA
//! Desktop, ASUS, Rider… e o editor de memória perdido no meio. Não é detecção;
//! é um jeito caro de ensinar o operador a ignorar o canal.
//!
//! Então a primeira varredura da sessão **não alerta**: ela fotografa o normal
//! daquela máquina (`6031`) e a partir daí só fala de quem chegou depois. É o
//! mesmo movimento que fez a 6.2 funcionar, e a razão é a mesma: quem já estava
//! lá quando o jogo abriu é o cenário; quem aparece no minuto dez é o evento.
//!
//! # O que isto ainda não vence
//!
//! * **Driver de kernel.** Um cheat em modo kernel lê a memória sem abrir handle
//!   nenhum. Nada em modo usuário vê isso — é o limite declarado no RSE_SPEC §2.
//! * **Cheat que já está dentro** (DLL injetada, código mapeado à mão): ele não
//!   precisa de handle externo. Isso é trabalho da 6.2 e da 6.5.
//! * **🚨 Cheat rodando ELEVADO.** Esta é nova, e é séria. O caminho de
//!   confirmação precisa abrir o processo dono com `PROCESS_DUP_HANDLE`, e um
//!   processo de integridade média — que é o nosso caso desde que tiramos o UAC
//!   — **não consegue abrir um processo elevado**. Numa medição real, 78% dos
//!   donos candidatos ficaram inacessíveis por isso.
//!
//!   Traduzindo sem rodeio: **Cheat Engine aberto como administrador não é
//!   visto por esta detecção.** E abrir o CE como administrador é o padrão em
//!   metade dos tutoriais.
//!
//!   As saídas possíveis, todas com custo: (a) o Loader voltar a exigir
//!   elevação — desfaz o trabalho de tirar o UAC e piora a vida do jogador
//!   honesto; (b) um serviço próprio rodando como sistema — mais peça para
//!   instalar e manter; (c) driver — outro projeto inteiro. Nenhuma delas é
//!   para agora, mas nenhuma delas deve ser esquecida: enquanto isso não for
//!   decidido, a 6.4b pega o cheat casual e **não** pega quem clicou em
//!   "executar como administrador".
//!
//! Continua valendo muito: cobre a **categoria inteira** de editor de memória
//! externo — que é o que se compra pronto — sem conhecer nenhum deles pelo nome.

#![cfg(windows)]

use std::collections::BTreeSet;
// `TryFrom` explícito: no edition 2018 ele não está no prelúdio.
use std::convert::TryFrom;
use std::time::Instant;

use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, OpenProcess};

use crate::sys;

/// `3003 REMOTE_HANDLE_WRITE_CAPABLE` — processo externo tem handle com poder de
/// escrita sobre o cliente.
///
/// **Não é o `3002 REMOTE_MEMORY_WRITE`** do RSE_SPEC §9, e a diferença importa:
/// o 3002 é para quando pegarmos uma escrita *acontecendo*; este é para quando
/// alguém **pode** escrever. Capacidade não é ato. Confundir os dois faria o log
/// afirmar mais do que a evidência sustenta — e é assim que se bane inocente.
const COD_HANDLE_ESCRITA: u16 = 3003;

/// Faixa experimental (6000–6999): handle com escrita cujo dono é infraestrutura
/// conhecida do Windows. Sai como informativo — visível, sem virar alerta.
///
/// **6030, não 6020** — o 6020 é o inventário de módulos do arranque
/// (`modulos.rs`). O registro vivo dos códigos fica em `rse/docs/CODIGOS.md`;
/// consulte-o antes de criar mais um. Esta é a segunda colisão da Fase 6, e as
/// duas foram pegas por acaso, não por processo.
const COD_HANDLE_INFRA: u16 = 6030;

/// `6031` — a linha de base tirada na primeira varredura da sessão.
///
/// Uma linha por sessão, informativa. Serve para o operador saber **quantos**
/// donos existiam antes de qualquer alerta — sem isso, um `3003` isolado não
/// diz se a máquina tinha 3 ou 300 processos com handle de escrita.
const COD_HANDLE_BASE: u16 = 6031;

// --- máscaras de acesso ------------------------------------------------------
//
// Estas quatro são as que dão poder de ESCRITA, direta ou indiretamente.
/// `CreateRemoteThread` — executa código nosso dentro do cliente.
const PROCESS_CREATE_THREAD: u32 = 0x0002;
/// `VirtualProtectEx` — torna uma página somente-leitura em gravável.
const PROCESS_VM_OPERATION: u32 = 0x0008;
/// `WriteProcessMemory` — o caso clássico do editor de memória.
const PROCESS_VM_WRITE: u32 = 0x0020;
/// Duplica handles nossos para si — escalada indireta.
const PROCESS_DUP_HANDLE: u32 = 0x0040;

const MASCARA_PERIGOSA: u32 =
    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// `SystemExtendedHandleInformation`.
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
/// `STATUS_INFO_LENGTH_MISMATCH` — buffer pequeno, tente maior.
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1_073_741_820; // 0xC0000004

/// Teto do buffer da tabela de handles: 96 MB.
///
/// Uma máquina normal usa 2–8 MB. O teto existe para que uma resposta absurda
/// não vire alocação sem fim **dentro do processo do jogo**, onde
/// `panic = 'abort'` transforma falha de alocação em cliente fechado.
const TETO_BUFFER: usize = 96 * 1024 * 1024;

/// Nomes que legitimamente seguram handle com escrita em tudo.
///
/// ⚠️ Isto **não é lista de exclusão**, é lista de *classificação*. Quem está
/// aqui sai como informativo em vez de alerta, mas continua saindo. Por isso um
/// cheat que se chame `csrss.exe` não ganha nada: continua no relatório — e um
/// `csrss.exe` em PID estranho é justamente o que salta aos olhos de quem lê.
const INFRAESTRUTURA: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "taskmgr.exe",
    "msmpeng.exe",
    "securityhealthservice.exe",
    "nissrv.exe",
];

// ===========================================================================
//  Estado entre varreduras
// ===========================================================================

/// Guarda o buffer (para não realocar megabytes a cada minuto dentro do jogo),
/// quem já foi reportado (para relatar a **transição**, não o estado) e a
/// largura da tabela já descoberta.
pub struct Sentinela {
    buffer: Vec<usize>,
    ja_reportados: BTreeSet<(u32, String)>,
    /// PID do Loader. `None` = não descobrimos; neste caso não excluímos
    /// ninguém e o Loader aparece no relatório — ruidoso, mas honesto.
    pid_do_loader: Option<u32>,
    /// Descoberta na primeira varredura e reaproveitada. Ver `Largura`.
    largura: Option<Largura>,
    /// Nomes (em minúsculas) que já seguravam handle de escrita na primeira
    /// varredura da sessão. `None` = ainda não medimos.
    linha_de_base: Option<BTreeSet<String>>,
}

impl Sentinela {
    pub fn nova() -> Sentinela {
        let pid_do_loader = pid_do_pai();
        match pid_do_loader {
            Some(p) => sys::log_dll(&format!("handles: Loader identificado como pid {}", p)),
            None => {
                sys::log_dll("handles: nao descobri o pid do Loader; ele vai aparecer no relatorio")
            }
        }
        Sentinela {
            buffer: vec![0usize; 512 * 1024],
            ja_reportados: BTreeSet::new(),
            pid_do_loader,
            largura: None,
            linha_de_base: None,
        }
    }
}

/// Um dono de handle com poder de escrita sobre nós.
struct Intruso {
    pid: u32,
    nome: String,
    acesso: u32,
}

/// Handle para o próprio processo, fechado ao sair de escopo.
///
/// Existe para que os `return` de erro no meio de `varrer` não vazem handle.
/// Um vazamento aqui seria discreto e cumulativo: uma varredura por minuto,
/// numa sessão de horas, são centenas de handles órfãos — e cada um deles é
/// mais uma entrada nossa na tabela que a própria varredura percorre.
struct HandleProprio(winapi::um::winnt::HANDLE);

impl Drop for HandleProprio {
    fn drop(&mut self) {
        // SAFETY: só construímos isto com um handle válido de OpenProcess.
        unsafe { winapi::um::handleapi::CloseHandle(self.0) };
    }
}

// ===========================================================================
//  A largura da tabela — a lição que este arquivo custou
// ===========================================================================

/// Em que largura o kernel devolveu a tabela de handles.
///
/// # Por que isto existe (e por que a primeira versão errou feio)
///
/// A primeira versão declarava uma `struct` com `usize` e confiava que, num
/// processo 32 bits, a tabela viria em 32 bits. Parece óbvio e está errado: o
/// Ragexe é 32 bits rodando sob **WOW64** num Windows 64 bits, e a tabela de
/// handles é uma estrutura do **kernel**, que é 64 bits. Nem toda versão do
/// Windows converte esta classe na travessia.
///
/// O sintoma não foi um erro. Foi pior: a varredura **acusou processos
/// inocentes**. Lendo campos de 8 bytes como se fossem de 4, as leituras caem
/// em posições deslocadas mas *plausíveis*, e o resultado foram handles de
/// **arquivo** (`0x12019f` = `FILE_GENERIC_READ|WRITE`) e de **evento**
/// (`0x100002`) apresentados como se fossem handles de processo com poder de
/// escrita. `ssh.exe`, `cargo.exe` e `chrome.exe` foram denunciados por terem
/// um console aberto.
///
/// Num anti-cheat, esse é o pior defeito possível: não deixar de pegar o
/// culpado é ruim; **apontar o inocente** é o que faz o operador banir quem não
/// devia e perder a confiança na ferramenta inteira.
///
/// Então não adivinhamos mais: lemos a tabela nas duas larguras, conferimos
/// qual delas produz PIDs que existem de verdade, e **recusamos relatar** se
/// nenhuma convencer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Largura {
    /// `ULONG_PTR` = 4 bytes. Cabeçalho 8, entrada 28.
    B32,
    /// `ULONG_PTR` = 8 bytes. Cabeçalho 16, entrada 40.
    B64,
}

impl Largura {
    fn cabecalho(self) -> usize {
        match self {
            Largura::B32 => 8,
            Largura::B64 => 16,
        }
    }
    fn passo(self) -> usize {
        match self {
            Largura::B32 => 28,
            Largura::B64 => 40,
        }
    }
    fn nome(self) -> &'static str {
        match self {
            Largura::B32 => "32",
            Largura::B64 => "64",
        }
    }
}

/// Uma entrada da tabela, já normalizada para 64 bits.
struct Entrada {
    objeto: u64,
    dono_pid: u64,
    valor_handle: u64,
    acesso: u32,
    /// Índice do **tipo** do objeto (Process, File, Event, …).
    ///
    /// A primeira versão ignorou este campo de propósito, com o argumento de
    /// que casar o ponteiro do objeto já garantia o tipo. O argumento só vale
    /// se a âncora for mesmo um processo — e quando a leitura sai torta, não é.
    /// O número do índice muda entre versões do Windows, então não o comparamos
    /// com constante nenhuma: comparamos com o tipo da **nossa própria âncora**.
    tipo: u16,
}

/// Lê uma entrada a partir do início dela.
///
/// # SAFETY
///
/// `p` tem que apontar para pelo menos `l.passo()` bytes legíveis. Todas as
/// leituras são `read_unaligned`: o buffer é `Vec<usize>` (alinhado a 4 bytes
/// num processo 32 bits) e o layout B64 tem campos de 8 bytes em offsets que
/// não respeitam esse alinhamento. Ler alinhado ali seria comportamento
/// indefinido.
unsafe fn ler_entrada(p: *const u8, l: Largura) -> Entrada {
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

/// Quantas entradas a tabela declara, na largura `l`.
///
/// # SAFETY
/// `base` precisa apontar para o começo do buffer preenchido pela API.
unsafe fn total_declarado(base: *const u8, l: Largura) -> u64 {
    match l {
        Largura::B32 => (base as *const u32).read_unaligned() as u64,
        Largura::B64 => (base as *const u64).read_unaligned(),
    }
}

/// Quão plausível é ler a tabela nesta largura, de 0.0 a 1.0.
///
/// Mede a fração das entradas amostradas cujo `dono_pid` é um processo que
/// **existe de verdade** agora. Numa leitura correta isso beira 1.0 — a tabela
/// é viva, todo handle tem dono. Numa leitura torta os campos caem em pedaços
/// de ponteiro e quase nada bate.
///
/// Amostra em vez de percorrer tudo: com ~100 mil entradas, 2000 amostras
/// espalhadas já separam 0.99 de 0.05 com folga, e custam quase nada.
unsafe fn confianca(base: *const u8, bytes: usize, l: Largura, vivos: &BTreeSet<u32>) -> f32 {
    let cabem = bytes.saturating_sub(l.cabecalho()) / l.passo();
    let n = total_declarado(base, l).min(cabem as u64) as usize;
    if n == 0 {
        return 0.0;
    }
    const AMOSTRAS: usize = 2000;
    let passo = (n / AMOSTRAS).max(1);

    let mut olhadas = 0usize;
    let mut batem = 0usize;
    let mut i = 0usize;
    while i < n {
        let e = ler_entrada(base.add(l.cabecalho() + i * l.passo()), l);
        olhadas += 1;
        // PID de verdade cabe em 32 bits e é múltiplo de 4 no Windows. As duas
        // condições sozinhas já derrubam metade do lixo; a checagem contra a
        // lista de processos vivos derruba o resto.
        if e.dono_pid <= u32::MAX as u64 && vivos.contains(&(e.dono_pid as u32)) {
            batem += 1;
        }
        i += passo;
    }
    if olhadas == 0 {
        0.0
    } else {
        batem as f32 / olhadas as f32
    }
}

/// Abaixo disto não relatamos nada. Numa leitura correta a confiança fica
/// perto de 1.0; o piso existe só para tolerar processos que morreram entre a
/// foto da tabela e a lista de processos.
const CONFIANCA_MINIMA: f32 = 0.80;

// ===========================================================================
//  Varredura
// ===========================================================================

/// Varre a tabela de handles e devolve as linhas de REPORT dos donos **novos**.
///
/// `Err` = a varredura não pôde ser feita **ou não pôde ser confiada**. Não
/// acusa ninguém: o chamador só registra e tenta de novo no próximo tique.
pub fn varrer(s: &mut Sentinela) -> Result<Vec<String>, String> {
    let t0 = Instant::now();

    // SAFETY: sem parâmetros, não falha.
    let nosso_pid = unsafe { GetCurrentProcessId() };
    let pid_do_loader = s.pid_do_loader;

    // Precisamos da lista de processos ANTES da tabela: é ela que decide qual
    // largura de leitura faz sentido (ver `confianca`).
    let mapa = crate::processos::mapa_pid_nome()
        .ok_or_else(|| "nao consegui listar os processos".to_string())?;
    let vivos: BTreeSet<u32> = mapa.keys().copied().collect();

    // 🚨 A ORDEM DESTAS DUAS OPERAÇÕES É O CORAÇÃO DA FUNÇÃO.
    //
    // Primeiro **abrir** o handle, depois **fotografar** a tabela. Ao contrário
    // não funciona nunca: `NtQuerySystemInformation` devolve um retrato do
    // instante em que é chamada, então um handle criado depois simplesmente não
    // está nele — e a busca pela âncora falha em 100% das execuções.
    //
    // Foi assim que este arquivo nasceu, e o sintoma foi honesto justamente
    // porque a âncora é obrigatória: sem ela a varredura devolve erro em vez de
    // "nenhum intruso". Se o código tivesse tratado âncora ausente como "tudo
    // limpo", a detecção teria ficado calada para sempre e o log diria que o
    // cliente estava seguro. É a diferença entre uma detecção quebrada e uma
    // detecção quebrada **que mente**.
    //
    // SAFETY: abrir o próprio processo para consulta é sempre permitido.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, nosso_pid) };
    if h.is_null() {
        return Err("nao consegui abrir um handle para mim mesmo".to_string());
    }
    // A partir daqui o handle é fechado por `Drop`, inclusive nos `return` de
    // erro abaixo.
    let guarda = HandleProprio(h);
    let valor = guarda.0 as u64;

    let bytes_uteis = carregar_tabela(s)?;
    let base = s.buffer.as_ptr() as *const u8;

    // --- qual largura? ------------------------------------------------------
    //
    // Descobrimos uma vez e guardamos: a resposta não muda no meio da sessão, e
    // a amostragem, embora barata, não precisa repetir todo minuto.
    let largura = match s.largura {
        Some(l) => l,
        None => {
            // SAFETY: `base` aponta para o buffer preenchido; `bytes_uteis` é o
            // tamanho que passamos à API.
            let (c32, c64) = unsafe {
                (
                    confianca(base, bytes_uteis, Largura::B32, &vivos),
                    confianca(base, bytes_uteis, Largura::B64, &vivos),
                )
            };
            let (melhor, conf) = if c64 > c32 {
                (Largura::B64, c64)
            } else {
                (Largura::B32, c32)
            };
            sys::log_dll(&format!(
                "handles: confianca 32bits={:.2} 64bits={:.2} -> escolhi {} bits",
                c32,
                c64,
                melhor.nome()
            ));
            if conf < CONFIANCA_MINIMA {
                return Err(format!(
                    "nao entendi o formato da tabela (confianca 32b={:.2} 64b={:.2}); \
                     nao vou relatar nada em cima de leitura duvidosa",
                    c32, c64
                ));
            }
            s.largura = Some(melhor);
            melhor
        }
    };

    // --- passadas -----------------------------------------------------------
    let cabem = bytes_uteis.saturating_sub(largura.cabecalho()) / largura.passo();
    // SAFETY: buffer preenchido pela API, largura já validada acima.
    let declarado = unsafe { total_declarado(base, largura) };
    // O `min` não é enfeite: se a API informasse mais entradas do que cabem,
    // ler além do buffer dentro do processo do jogo é falha de página, não
    // mensagem de erro.
    let total = declarado.min(cabem as u64) as usize;

    let mut ancora: Option<(u64, u16)> = None;
    let mut minhas: usize = 0;
    for i in 0..total {
        // SAFETY: i < total <= cabem, então a entrada está dentro do buffer.
        let e = unsafe { ler_entrada(base.add(largura.cabecalho() + i * largura.passo()), largura) };
        if e.dono_pid != nosso_pid as u64 {
            continue;
        }
        minhas += 1;
        if e.valor_handle == valor {
            ancora = Some((e.objeto, e.tipo));
        }
    }

    let (objeto_nosso, tipo_processo) = match ancora {
        Some(a) => a,
        None => {
            return Err(format!(
                "nao achei o meu proprio handle (0x{:x}) entre as {} entrada(s) minhas, \
                 de {} no total, lendo em {} bits",
                valor,
                minhas,
                total,
                largura.nome()
            ))
        }
    };

    // O handle já cumpriu o papel de âncora.
    drop(guarda);

    // 🚨 PONTEIRO REDIGIDO — a armadilha que quase passou como detecção boa.
    //
    // O Windows zera os ponteiros de kernel desta tabela para quem chama sem
    // elevação. Como o Loader roda `asInvoker` (tiramos o UAC de propósito), é
    // o nosso caso: `Object` volta **0 em todas as entradas**.
    //
    // Com âncora 0, o teste `e.objeto == objeto_nosso` vira `0 == 0` — e casa
    // com tudo. O que sobrava filtrando era só "é handle de processo e tem
    // máscara de escrita", o que responde a pergunta ERRADA:
    //
    //   perguntamos : quem tem handle para o JOGO?
    //   respondíamos: quem tem handle para QUALQUER processo?
    //
    // Numa máquina real isso deu **145 processos** — `git.exe` segurando o
    // próprio filho, `conhost.exe` segurando o seu, `cargo.exe` idem. O jogo
    // nunca entrou na conta. E o mais perigoso: a lista *parecia* plausível,
    // porque cada linha era um processo de verdade com uma máscara de verdade.
    //
    // Por isso a âncora zerada agora derruba o caminho rápido em vez de ser
    // aceita em silêncio.
    let brutos = if objeto_nosso != 0 {
        // Caminho rápido: comparação de ponteiro, uma passada, sem syscall.
        let mut v: Vec<(u32, u32)> = Vec::new();
        for i in 0..total {
            // SAFETY: mesma justificativa da passada anterior.
            let e =
                unsafe { ler_entrada(base.add(largura.cabecalho() + i * largura.passo()), largura) };
            if e.tipo != tipo_processo || e.objeto != objeto_nosso {
                continue;
            }
            if let Some(x) = filtrar(&e, nosso_pid, pid_do_loader) {
                v.push(x);
            }
        }
        v
    } else {
        // Caminho lento: o ponteiro não serve, então **perguntamos ao Windows**
        // para onde cada handle aponta.
        //
        // Duplicamos o handle do dono para dentro de nós e comparamos
        // `GetProcessId` com o nosso PID. É uma syscall por candidato — caro, e
        // é por isso que só entram aqui os que já passaram pelo filtro de tipo e
        // de máscara. Na máquina que gerou os 145, isso são algumas centenas de
        // duplicações, uma vez por minuto.
        //
        // Duplicar exige `PROCESS_DUP_HANDLE` sobre o dono, o que falha para
        // `System`, `csrss` e processos protegidos. Falhou = **não sei**, e não
        // sei nunca vira acusação: o candidato é descartado e contado à parte,
        // para o log dizer quantos ficaram sem resposta.
        let mut candidatos: Vec<(u32, u64, u32)> = Vec::new();
        for i in 0..total {
            // SAFETY: mesma justificativa da passada anterior.
            let e =
                unsafe { ler_entrada(base.add(largura.cabecalho() + i * largura.passo()), largura) };
            if e.tipo != tipo_processo {
                continue;
            }
            if let Some((dono, acesso)) = filtrar(&e, nosso_pid, pid_do_loader) {
                candidatos.push((dono, e.valor_handle, acesso));
            }
        }
        let (v, sem_resposta) = confirmar_alvo(&candidatos, nosso_pid);
        sys::log_dll(&format!(
            "handles: ponteiro redigido; confirmei {} de {} candidato(s) por duplicacao \
             ({} sem permissao)",
            v.len(),
            candidatos.len(),
            sem_resposta
        ));
        v
    };

    // Um dono pode ter vários handles para nós; interessa o dono, não a contagem.
    let mut vistos_agora: BTreeSet<(u32, String)> = BTreeSet::new();
    let mut intrusos: Vec<Intruso> = Vec::new();
    for (pid, acesso) in brutos {
        let nome = mapa
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| format!("<pid {} sem nome>", pid));
        if vistos_agora.insert((pid, nome.clone())) {
            intrusos.push(Intruso { pid, nome, acesso });
        }
    }

    sys::log_dll(&format!(
        "handles: {} entradas ({} minhas, tipo processo={}) em {} ms, {} dono(s) com escrita",
        total,
        minhas,
        tipo_processo,
        t0.elapsed().as_millis(),
        intrusos.len()
    ));

    // --- primeira varredura: isto é a LINHA DE BASE, não um alerta ----------
    //
    // Na estreia da 6.4b esta lista tinha **95 donos** numa máquina limpa:
    // svchost, conhost, chrome, msedgewebview2, Riot Client, EA Desktop, ASUS,
    // Rider… e o cheat perdido no meio deles. 95 alertas por varredura não é
    // detecção, é um jeito caro de treinar o operador a ignorar o canal.
    //
    // A saída é a mesma que fez a 6.2 funcionar: fotografar o normal e depois
    // só falar do que mudou. Um processo que já segurava handle quando o jogo
    // abriu é o cenário da máquina; o editor de memória que alguém anexa no
    // minuto dez, não.
    //
    // Repare que a base é por **nome**, não por PID. `conhost.exe` e
    // `cargo.exe` nascem e morrem o tempo todo — casar por PID faria cada
    // processo novo virar alerta, e a base não serviria para nada. O custo
    // dessa escolha está anotado logo abaixo, na classificação.
    if s.linha_de_base.is_none() {
        let nomes: BTreeSet<String> = intrusos.iter().map(|i| i.nome.to_ascii_lowercase()).collect();
        // Registra os NOMES distintos, não um por dono. Numa máquina com 95
        // donos, listar cada um enchia o log de 95 linhas por sessão para dizer
        // a mesma coisa que 41 dizem — e o PID de um processo de fundo não
        // ajuda em nada depois que a sessão acabou.
        sys::log_dll(&format!("handles: base ({} nomes): {}", nomes.len(), {
            let v: Vec<&str> = nomes.iter().map(|s| s.as_str()).collect();
            v.join(", ")
        }));
        let quantos = intrusos.len();
        let nomes_distintos = nomes.len();
        s.linha_de_base = Some(nomes);
        s.ja_reportados.clear();
        return Ok(vec![format!(
            "{}|info|linha de base de handles: {} dono(s), {} nome(s) distintos",
            COD_HANDLE_BASE, quantos, nomes_distintos
        )]);
    }

    let base = match &s.linha_de_base {
        Some(b) => b,
        None => return Ok(Vec::new()), // impossível: acabamos de tratar o None
    };

    let mut linhas = Vec::new();
    for i in &intrusos {
        if !s.ja_reportados.insert((i.pid, i.nome.clone())) {
            continue; // já relatado nesta sessão
        }
        // Duas formas de ser "esperado": estar na base desta máquina, ou ser
        // infraestrutura conhecida do Windows.
        //
        // ⚠️ Aqui mora o preço da base por nome: um cheat batizado de
        // `conhost.exe` cai no ramo informativo, porque um conhost de verdade
        // está na base. Continua **aparecendo** no relatório — só não como
        // alerta. É o mesmo compromisso da lista `INFRAESTRUTURA`: classificar
        // em vez de esconder, para o operador poder julgar.
        let conhecido = base.contains(&i.nome.to_ascii_lowercase())
            || INFRAESTRUTURA.iter().any(|n| i.nome.eq_ignore_ascii_case(n));
        let (cod, sev) = if conhecido {
            (COD_HANDLE_INFRA, "info")
        } else {
            (COD_HANDLE_ESCRITA, "alta")
        };
        linhas.push(format!(
            "{}|{}|handle com escrita no cliente: {} (pid {}) acesso=0x{:x} [{}]",
            cod,
            sev,
            i.nome,
            i.pid,
            i.acesso,
            descrever_acesso(i.acesso)
        ));
    }

    // Quem sumiu deixa de contar como reportado, para que voltar a aparecer gere
    // linha nova. Sem isto, fechar e reabrir o editor na mesma sessão seria
    // invisível depois da primeira vez.
    s.ja_reportados.retain(|c| vistos_agora.contains(c));

    Ok(linhas)
}

/// Traduz a máscara para algo legível sem consultar documentação.
fn descrever_acesso(a: u32) -> String {
    let mut v: Vec<&str> = Vec::new();
    if a & PROCESS_VM_WRITE != 0 {
        v.push("VM_WRITE");
    }
    if a & PROCESS_VM_OPERATION != 0 {
        v.push("VM_OPERATION");
    }
    if a & PROCESS_CREATE_THREAD != 0 {
        v.push("CREATE_THREAD");
    }
    if a & PROCESS_DUP_HANDLE != 0 {
        v.push("DUP_HANDLE");
    }
    v.join(" ")
}

// ===========================================================================
//  A chamada ao kernel
// ===========================================================================

type NtQuerySystemInformation = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

/// Preenche `s.buffer` com a tabela de handles, crescendo se preciso.
/// Devolve quantos **bytes** do buffer são utilizáveis.
fn carregar_tabela(s: &mut Sentinela) -> Result<usize, String> {
    let endereco = sys::endereco_de("ntdll.dll", "NtQuerySystemInformation")
        .ok_or_else(|| "NtQuerySystemInformation nao resolveu".to_string())?;
    // SAFETY: símbolo obtido por GetProcAddress no ntdll; assinatura estável.
    let f: NtQuerySystemInformation = unsafe { std::mem::transmute(endereco) };

    loop {
        let bytes = s.buffer.len() * std::mem::size_of::<usize>();
        let mut devolvido: u32 = 0;
        // SAFETY: o buffer tem `bytes` bytes válidos e alinhamento de `usize`.
        // Todas as leituras posteriores são `read_unaligned`, então o
        // alinhamento do buffer não precisa casar com o do layout escolhido.
        let status = unsafe {
            f(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                s.buffer.as_mut_ptr() as *mut c_void,
                bytes as u32,
                &mut devolvido,
            )
        };

        if status == 0 {
            return Ok(bytes);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(format!("NtQuerySystemInformation devolveu 0x{:x}", status));
        }

        let novo = (bytes * 2).max(devolvido as usize + 64 * 1024);
        if novo > TETO_BUFFER {
            return Err(format!("tabela de handles acima do teto ({} B)", novo));
        }
        s.buffer
            .resize(novo / std::mem::size_of::<usize>() + 1, 0usize);
    }
}

// ===========================================================================
//  PID do pai (o Loader)
// ===========================================================================

#[repr(C)]
struct InformacaoBasicaDeProcesso {
    status_de_saida: i32,
    base_do_peb: *mut c_void,
    mascara_de_afinidade: usize,
    prioridade_base: i32,
    pid: usize,
    pid_do_pai: usize,
}

type NtQueryInformationProcess =
    unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;

/// PID do processo que criou este — o Loader.
///
/// Aqui a largura não é problema: `ProcessBasicInformation` é uma das classes
/// que o WOW64 converte, então um processo 32 bits recebe campos de 32 bits.
///
/// `None` = não deu para descobrir. Nunca chuta: sem isto o Loader entra no
/// relatório como qualquer outro, o que é ruidoso mas verdadeiro.
fn pid_do_pai() -> Option<u32> {
    let endereco = sys::endereco_de("ntdll.dll", "NtQueryInformationProcess")?;
    // SAFETY: símbolo do ntdll com assinatura estável desde o XP.
    let f: NtQueryInformationProcess = unsafe { std::mem::transmute(endereco) };

    // SAFETY: struct POD; a API a preenche.
    let mut info: InformacaoBasicaDeProcesso = unsafe { std::mem::zeroed() };
    let mut devolvido: u32 = 0;
    // SAFETY: `info` tem o tamanho declarado; handle do próprio processo.
    let status = unsafe {
        f(
            GetCurrentProcess() as *mut c_void,
            0, // ProcessBasicInformation
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<InformacaoBasicaDeProcesso>() as u32,
            &mut devolvido,
        )
    };
    if status != 0 {
        return None;
    }
    Some(info.pid_do_pai as u32)
}

/// Filtros que valem nos dois caminhos: não somos nós, não é o Loader, e a
/// máscara dá poder de escrita.
fn filtrar(e: &Entrada, nosso_pid: u32, pid_do_loader: Option<u32>) -> Option<(u32, u32)> {
    let dono = u32::try_from(e.dono_pid).ok()?;
    if dono == nosso_pid {
        return None; // os nossos próprios handles
    }
    if Some(dono) == pid_do_loader {
        return None; // o Loader, identificado pelo PPID
    }
    if e.acesso & MASCARA_PERIGOSA == 0 {
        return None; // só consulta/leitura: não é o que procuramos
    }
    Some((dono, e.acesso))
}

/// Confirma, um a um, quais candidatos apontam mesmo para **nós**.
///
/// Duplica o handle do dono para dentro deste processo e pergunta
/// `GetProcessId`. É a resposta do próprio Windows — não depende de ponteiro,
/// de nome, nem de suposição sobre layout.
///
/// Devolve `(confirmados, quantos_ficaram_sem_resposta)`. Um dono que não
/// conseguimos abrir entra no segundo número, nunca no primeiro: falta de
/// permissão é ignorância, não inocência **nem** culpa.
fn confirmar_alvo(candidatos: &[(u32, u64, u32)], nosso_pid: u32) -> (Vec<(u32, u32)>, usize) {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, GetProcessId};
    use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, HANDLE};

    const PROCESS_DUP_HANDLE: u32 = 0x0040;

    let mut confirmados = Vec::new();
    let mut sem_resposta = 0usize;

    // Ordenar por dono é o que faz o cache abaixo valer alguma coisa.
    //
    // Numa medição real: **4286 candidatos** numa máquina comum, mas só algumas
    // centenas de donos distintos. Sem ordenar, os candidatos vêm na ordem da
    // tabela do kernel — embaralhados — e o cache de "processo já aberto" quase
    // nunca acerta, o que dá um `OpenProcess` por candidato. Ordenando, dá um
    // por **dono**: uma redução de quase 10×, dentro do processo do jogo.
    let mut ordenados: Vec<&(u32, u64, u32)> = candidatos.iter().collect();
    ordenados.sort_by_key(|(dono, _, _)| *dono);

    // `Some(None)` = já tentamos abrir este dono e NÃO deu. Guardar a falha
    // importa tanto quanto guardar o sucesso: 78% dos donos numa máquina real
    // são inacessíveis, e sem isto pagaríamos um `OpenProcess` fadado ao erro
    // para cada handle deles.
    let mut dono_atual: Option<(u32, Option<HANDLE>)> = None;

    for (dono, valor, acesso) in ordenados {
        let aberto = match dono_atual {
            Some((p, h)) if p == *dono => h,
            _ => {
                if let Some((_, Some(h))) = dono_atual.take() {
                    // SAFETY: handle que abrimos na volta anterior.
                    unsafe { CloseHandle(h) };
                }
                // SAFETY: abrir processo alheio só para duplicar; pode falhar, e
                // falhar aqui é esperado (System, csrss, protegidos, elevados).
                let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, *dono) };
                let r = if h.is_null() { None } else { Some(h) };
                dono_atual = Some((*dono, r));
                r
            }
        };

        let origem = match aberto {
            Some(h) => h,
            None => {
                sem_resposta += 1;
                continue;
            }
        };

        let mut copia: HANDLE = std::ptr::null_mut();
        // SAFETY: `origem` é válido; `valor` veio da tabela como handle daquele
        // processo; `copia` recebe o duplicado, que fechamos abaixo.
        let ok = unsafe {
            winapi::um::handleapi::DuplicateHandle(
                origem,
                *valor as HANDLE,
                GetCurrentProcess(),
                &mut copia,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 || copia.is_null() {
            sem_resposta += 1;
            continue;
        }

        // SAFETY: `copia` é um handle de processo válido que acabamos de criar.
        let alvo = unsafe { GetProcessId(copia) };
        // SAFETY: idem; devolvemos o handle imediatamente.
        unsafe { CloseHandle(copia) };

        if alvo == nosso_pid {
            confirmados.push((*dono, *acesso));
        }
    }

    if let Some((_, Some(h))) = dono_atual {
        // SAFETY: último handle de dono ainda aberto.
        unsafe { CloseHandle(h) };
    }

    (confirmados, sem_resposta)
}
