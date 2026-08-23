//! Fase 6.4 — Processos proibidos (`3000 FORBIDDEN_PROCESS`).
//!
//! # O que esta detecção faz
//!
//! Varre a lista de processos em execução e compara os nomes (sem distinção de
//! maiúsculas/minúsculas) contra uma lista curada de ferramentas de trapaça
//! conhecidas. Quando encontra alguma, gera uma linha de `REPORT`.
//!
//! # O que esta lista **não** inclui, e por quê
//!
//! * **Depuradores** (x64dbg, OllyDbg, Visual Studio): a Fase 6.1 já cobre
//!   isso de dentro — detecta `DebugActiveProcess` sobre o *nosso* processo, que
//!   é muito mais preciso do que o nome do executável. Um depurador aberto sem
//!   estar anexado ao jogo não é ameaça.
//! * **Process Hacker / System Informer**: ferramentas legítimas de diagnóstico
//!   que muitos usuários avançados usam por padrão. Falso-positivo demais.
//! * **Ferramentas de rede genéricas** (Wireshark, Fiddler): a proteção de
//!   canal (AES-GCM + ticket) mitiga o risco; bloquear Wireshark pelo nome
//!   derrubaria desenvolvedores e streamers sem culpa.
//!
//! # Limite honesto desta detecção
//!
//! Renomear o executável passa por esta lista inteiro. É o mesmo limite de
//! qualquer blocklist de nome — serve para o cheater casual, não para quem se
//! prepara. O valor é rastreio, não barreira: uma conta que frequentemente abre
//! com Cheat Engine rodando merece atenção, mesmo que o cheat em si não esteja
//! ativo naquele momento.
//!
//! # Por que não usar hashes de executável
//!
//! O Cheat Engine é open-source e compilado por qualquer pessoa; há dezenas de
//! variantes por versão. O WPE Pro circula em tantos repacks que qualquer hash
//! fica defasado em dias. Nome é impreciso, mas hash seria um esforço de
//! manutenção contínua para pouco ganho adicional nesta fase.

#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};

use winapi::shared::minwindef::MAX_PATH;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::HANDLE;

/// `3000 FORBIDDEN_PROCESS` — processo proibido em execução.
///
/// O código vem do RSE_SPEC §9, que já o reservava (severidade **alta**, ação
/// padrão *warn + report*) desde a Fase 1 — esta detecção é a implementação
/// dele, não um código novo.
///
/// Faixa 3000–3999 = ambiente **externo** ao processo (o que está rodando na
/// máquina). Compare com a 2000–2999, que é o que foi carregado **dentro** do
/// nosso processo. `3001 DEBUGGER_ATTACHED`, da Fase 6.1, é vizinho de porta
/// justamente por isso.
const COD_PROCESSO_PROIBIDO: u16 = 3000;

/// Lista de nomes de executável proibidos, todos em minúsculas.
///
/// A comparação é `eq_ignore_ascii_case`, então a capitalização aqui é só
/// para legibilidade. Colocamos comentário em cada entrada para que o motivo
/// da inclusão fique claro — sem comentário, não entra.
const PROIBIDOS: &[&str] = &[
    // === Editores de memória ===============================================
    //
    // Cheat Engine — o editor de memória mais usado para MMORPG. Permite
    // encontrar e alterar HP, zeny, velocidade, delay de skill em tempo real.
    // Open-source, compilado em mil variantes; os nomes abaixo cobrem as
    // distribuições oficiais e as mais comuns em fóruns.
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "cheatengine.exe",
    "cheatengine64.exe",
    // ArtMoney — editor de memória popular especificamente para jogos antigos
    // (inclui Ragnarok Online em sua lista de "jogos suportados").
    "artmoney.exe",
    "artmoneySE.exe",
    "artmoneypro.exe",
    // TSearch — editor de memória histórico, muito usado no RO clássico para
    // localizar o ponteiro de HP e zeny.
    "tsearch.exe",
    // Usurper — fork do TSearch com interface modernizada.
    "usurper.exe",

    // === Editores de pacote (packet editors) ================================
    //
    // WPE Pro — o editor de pacotes mais usado historicamente no Ragnarok.
    // Intercepta e modifica o tráfego TCP em nível de socket, permitindo
    // duplicar ações, forjar movimentos e injetar pacotes de NPC. Não há
    // uso legítimo deste programa junto com o jogo.
    "wpepro.exe",
    "wpe pro.exe",
    // RPE (Ragnarok Packet Editor) — fork do WPE adaptado especificamente
    // para o protocolo do RO.
    "rpe.exe",

    // === Injetores de DLL ===================================================
    //
    // Extreme Injector — ferramenta dedicada a injetar DLLs arbitrárias em
    // processos. Não tem uso legítimo junto com um cliente de jogo.
    "extreme injector.exe",
    // Xenos Injector — injetor moderno com suporte a múltiplos métodos
    // (SetWindowsHookEx, QueueUserAPC, CreateRemoteThread manual etc.).
    "xenos.exe",
    "xenos64.exe",
    "xenos injector.exe",
    // GH Injector — injetor popular em comunidades de cheat para jogos
    // competitivos; começa a aparecer em fóruns de RO privado.
    "gh injector.exe",
    "gh injector - x86.exe",
    "gh injector - x64.exe",
];

/// O que uma varredura encontrou: conjunto de nomes de processo proibidos
/// que estão *agora* em execução (em minúsculas, para comparação posterior).
pub struct Achados {
    pub processos: BTreeSet<String>,
}

impl Achados {
    pub fn limpo(&self) -> bool {
        self.processos.is_empty()
    }
}

/// Varre a lista de processos do sistema e devolve os nomes proibidos que
/// estão em execução agora.
///
/// `None` = não foi possível criar o snapshot (sem privilégios ou falha de
/// API); neste caso a detecção é silenciada — melhor falhar aberto do que
/// acusar em cima de erro de sistema.
pub fn procurar_proibidos() -> Option<Achados> {
    let snap = criar_snapshot()?;
    let nomes: Vec<String> = listar(snap).into_iter().map(|(_, n)| n).collect();
    // SAFETY: snap é válido; CloseHandle é sempre seguro neste ponto.
    unsafe { CloseHandle(snap) };

    let mut encontrados = BTreeSet::new();
    for nome in &nomes {
        let minusc = nome.to_ascii_lowercase();
        if PROIBIDOS.iter().any(|p| minusc == *p) {
            encontrados.insert(minusc);
        }
    }
    Some(Achados { processos: encontrados })
}

/// Mapa `PID → nome do executável`, para quem precisa dar nome a um PID.
///
/// Vive aqui porque é aqui que já existe o trato com o Toolhelp. O consumidor
/// principal é o `handles.rs` da 6.4b: ele descobre **PIDs** que seguram handle
/// com escrita sobre o cliente, e um relatório que diz apenas "pid 7412" não
/// ajuda ninguém a decidir nada.
///
/// `None` = o snapshot falhou. Repare que é a mesma convenção do resto da Fase
/// 6: falha de API devolve "não sei", nunca uma lista vazia que pareceria
/// "nenhum processo rodando".
pub fn mapa_pid_nome() -> Option<BTreeMap<u32, String>> {
    let snap = criar_snapshot()?;
    let itens = listar(snap);
    // SAFETY: snap é válido; CloseHandle é sempre seguro neste ponto.
    unsafe { CloseHandle(snap) };
    Some(itens.into_iter().collect())
}

/// Traduz um conjunto de processos *novos* (ainda não reportados) em linhas
/// de REPORT.
///
/// Recebe apenas os nomes que apareceram desde a última varredura — a lógica
/// de "novo vs. visto" fica no canal, não aqui.
pub fn linhas_de_report(novos: &BTreeSet<String>) -> Vec<String> {
    novos
        .iter()
        .map(|nome| {
            format!(
                "{}|alta|processo proibido em execucao: {}",
                COD_PROCESSO_PROIBIDO, nome
            )
        })
        .collect()
}

// ===========================================================================
//  Helpers internos
// ===========================================================================

fn criar_snapshot() -> Option<HANDLE> {
    // SAFETY: TH32CS_SNAPPROCESS é a flag correta; 0 = todos os processos.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        None
    } else {
        Some(snap)
    }
}

/// Percorre o snapshot uma vez e devolve `(pid, nome)` de cada processo.
fn listar(snap: HANDLE) -> Vec<(u32, String)> {
    let mut nomes = Vec::new();
    // SAFETY: PROCESSENTRY32W é POD; dwSize deve ser preenchido antes do uso.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: snap é válido; entry tem o tamanho correto.
    if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
        return nomes;
    }

    loop {
        let fim = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(MAX_PATH);
        let nome = String::from_utf16_lossy(&entry.szExeFile[..fim]);
        nomes.push((entry.th32ProcessID, nome));

        // SAFETY: snap e entry continuam válidos.
        if unsafe { Process32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }

    nomes
}
