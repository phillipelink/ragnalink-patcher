//! Fase 6.5 — **o código ainda é o que era?** (`3002`, `2003`)
//!
//! # A lacuna que este arquivo fecha
//!
//! Todas as detecções anteriores perguntam *quem* está fazendo algo: qual
//! processo abriu um handle (6.4b), qual DLL foi carregada (6.2), qual programa
//! está rodando (6.4). Todas dependem de conseguir **enxergar o adversário**.
//!
//! E aí veio a medição que estragou o conforto: para confirmar o dono de um
//! handle, a 6.4b precisa abrir aquele processo — e um processo de integridade
//! média, que é o nosso desde que tiramos o UAC, **não abre um processo
//! elevado**. Foram 78% dos donos inacessíveis numa máquina real. Traduzindo:
//! *Cheat Engine aberto como administrador é invisível para ela* — e "executar
//! como administrador" é o que metade dos tutoriais manda fazer.
//!
//! Se todo cheater fizesse isso, a 6.4b viraria enfeite.
//!
//! # A pergunta que não depende de enxergar ninguém
//!
//! Em vez de *quem escreveu na nossa memória*, perguntamos **o que na nossa
//! memória mudou**. É a diferença entre vigiar a porta e conferir o cofre.
//!
//! Isso muda tudo, porque não exige privilégio nenhum: **é a nossa própria
//! memória**. Ler o nosso código é o direito mais básico que um processo tem.
//! Não importa se quem escreveu era administrador, era um driver de kernel, ou
//! chegou por um caminho que a gente nem imaginou — se o byte mudou, o byte
//! mudou, e nós vemos.
//!
//! | | 6.4b — handle | 6.5 — este arquivo |
//! |---|---|---|
//! | Pergunta | quem **pode** escrever | o que **foi** escrito |
//! | Evidência | capacidade | ato consumado |
//! | Precisa de privilégio | sim, sobre o dono | **não** |
//! | Cheat elevado | invisível | **visível** |
//! | Cheat com driver | invisível | **visível** (o efeito, não o autor) |
//! | Cheat que só *lê* memória | visível | invisível |
//!
//! As duas são complementares de propósito: a 6.4b pega quem se preparou para
//! ler (ESP, leitor de HP), a 6.5 pega quem escreveu (speedhack, patch de
//! delay, injeção). Nenhuma substitui a outra.
//!
//! # O que é medido
//!
//! **1. A seção de código do jogo.** O `.text` do Ragexe não muda depois de
//! carregado — é o próprio programa. Qualquer alteração ali é alguém remendando
//! o jogo: remover a checagem de delay, mudar o alcance de um ataque, desviar
//! uma função para código próprio.
//!
//! **2. A seção de código da nossa DLL.** Se um cheat quiser desligar o RSE, o
//! caminho mais direto é remendar as nossas próprias checagens — trocar um
//! `jne` por `jmp` e a detecção passa a nunca acusar. Conferir o próprio código
//! é o que impede que a proteção seja desarmada em silêncio.
//!
//! **3. O prólogo das funções do Windows de que dependemos.** É aqui que a 6.5
//! **protege as outras detecções**: um cheat que engancha `IsDebuggerPresent`
//! derruba a 6.1; que engancha `QueryPerformanceCounter` é o próprio speedhack
//! da 6.3; que engancha `NtQuerySystemInformation` cega a 6.4b. Todos aparecem
//! aqui como prólogo alterado.
//!
//! # 🚨 A linha de base tem que sair DEPOIS dos nossos próprios ganchos
//!
//! O netgate instala hooks inline em `send` e `WSASend` — de propósito, é assim
//! que o ticket entra no login. Se a foto fosse tirada antes disso, o RSE
//! acusaria a si mesmo em toda sessão, e o operador aprenderia a ignorar o
//! único código que significa "alguém remendou o jogo".
//!
//! Por isso a base sai dentro do `apertar_mao`, depois do netgate e antes do
//! `HELLO_ACK`: os nossos ganchos já estão no lugar, e o jogo ainda está
//! suspenso — ninguém de fora teve tempo de escrever nada.
//!
//! # O que isto não pega
//!
//! * **Quem só lê.** Um ESP que lê posições sem escrever nada não deixa rastro
//!   aqui. Quem pega esse é a 6.4b, pelo handle.
//! * **Código novo em memória alocada**, sem tocar no `.text` existente (manual
//!   mapping puro que não engancha nada). Vê-se pelo efeito quando ele
//!   eventualmente desvia alguma coisa; sozinho, não.
//! * **Driver que mente na leitura.** Se o kernel devolver os bytes antigos
//!   quando lemos, não há defesa em modo usuário. Limite do RSE_SPEC §2.

// Sem `#![cfg(windows)]`: a parte que decide o que mudou é pura e tem teste.
// Só a leitura da memória e a travessia do PE precisam do Windows.

use rse_protocol::crypto::sha256;

#[cfg(windows)]
use crate::sys;

/// `3002 REMOTE_MEMORY_WRITE` — a seção de código mudou depois da linha de base.
///
/// Este é o código que o RSE_SPEC §9 reservou para "alguém **escreveu** na
/// memória do cliente", em contraste com o `3003`, que é só capacidade. Aqui a
/// evidência é o ato: o byte era A no arranque e é B agora.
const COD_CODIGO_ALTERADO: u16 = 3002;

/// `2003 INLINE_HOOK_DETECTED` — o prólogo de uma função do Windows que usamos
/// foi desviado depois da linha de base.
const COD_HOOK: u16 = 2003;

/// Telemetria: tudo conferido e igual.
const COD_CODIGO_OK: u16 = 6060;

/// Quantos bytes do começo de cada função entram na conferência.
///
/// Um desvio inline clássico ocupa 5 bytes (`jmp rel32`); variantes com
/// `mov eax, addr; jmp eax` chegam a 12. 16 cobre as formas comuns sem entrar
/// no corpo da função, onde um `hotpatch` legítimo do Windows poderia mexer.
const BYTES_DE_PROLOGO: usize = 16;

/// As funções cujo prólogo vigiamos, e **por que cada uma importa**.
///
/// A lista não é "funções importantes em geral" — é exatamente aquilo de que
/// alguma detecção nossa depende. Enganchar qualquer uma delas é uma tentativa
/// de desarmar o RSE, não um efeito colateral.
#[cfg(windows)]
const FUNCOES_VIGIADAS: &[(&str, &str, &str)] = &[
    ("kernel32.dll", "IsDebuggerPresent", "6.1 — depurador"),
    ("ntdll.dll", "NtQueryInformationProcess", "6.1 — depurador pelo ntdll"),
    ("ntdll.dll", "NtQuerySystemInformation", "6.4b — tabela de handles"),
    ("kernel32.dll", "QueryPerformanceCounter", "6.3 — relogio"),
    ("kernel32.dll", "GetTickCount64", "6.3 — autoconferencia do relogio"),
    ("kernel32.dll", "CreateFileW", "leitura dos arquivos na integridade"),
    ("kernel32.dll", "ReadFile", "leitura dos arquivos na integridade"),
];

// ===========================================================================
//  A decisão — pura, testável em qualquer máquina
// ===========================================================================

/// Uma coisa vigiada e o resumo dela na linha de base.
#[derive(Clone, PartialEq, Debug)]
pub struct Marca {
    /// Como aparece no relatório.
    pub nome: String,
    /// `true` = seção de código; `false` = prólogo de função.
    pub e_secao: bool,
    /// Por que está sendo vigiada (só para o texto do relatório).
    pub motivo: String,
    pub hash: [u8; 32],
}

/// Compara duas fotos e devolve as linhas de REPORT das que mudaram.
///
/// Função pura: recebe base e atual, devolve o veredito. É aqui que a detecção
/// decide, e é isto que os testes exercitam — sem precisar remendar memória de
/// processo nenhum para provar que a comparação funciona.
///
/// Uma marca que sumiu do "atual" **não** é acusação: significa que não deu
/// para ler agora (módulo descarregado, página trocada). Não sei nunca vira
/// culpa — a mesma regra do resto da Fase 6.
pub fn comparar(base: &[Marca], atual: &[Marca]) -> Vec<String> {
    let mut linhas = Vec::new();

    for b in base {
        let a = match atual.iter().find(|x| x.nome == b.nome) {
            Some(a) => a,
            None => continue, // não deu para reler: não acusa
        };
        if a.hash == b.hash {
            continue;
        }
        if b.e_secao {
            linhas.push(format!(
                "{}|critica|codigo alterado em memoria: {} ({})",
                COD_CODIGO_ALTERADO, b.nome, b.motivo
            ));
        } else {
            linhas.push(format!(
                "{}|alta|funcao desviada: {} ({})",
                COD_HOOK, b.nome, b.motivo
            ));
        }
    }

    linhas
}

/// Linha informativa do arranque, dizendo o que entrou na vigilância.
pub fn linha_da_base(base: &[Marca]) -> String {
    let secoes = base.iter().filter(|m| m.e_secao).count();
    let funcoes = base.len() - secoes;
    format!(
        "{}|info|vigilancia de codigo: {} secao(oes) e {} funcao(oes) na linha de base",
        COD_CODIGO_OK, secoes, funcoes
    )
}

// ===========================================================================
//  A leitura — Windows
// ===========================================================================

/// Tira a foto de tudo que vigiamos.
///
/// Chamada duas vezes: uma no arranque (linha de base) e uma a cada varredura
/// cara. O que não der para ler simplesmente não entra na lista — e a
/// comparação trata ausência como "não sei", nunca como violação.
#[cfg(windows)]
pub fn fotografar() -> Vec<Marca> {
    let mut marcas = Vec::new();

    // --- 1. o código do jogo ------------------------------------------------
    // SAFETY: NULL devolve o módulo do próprio processo — o Ragexe.
    let base_exe = unsafe { winapi::um::libloaderapi::GetModuleHandleW(std::ptr::null()) } as usize;
    if let Some(m) = marcar_secao_de_codigo(base_exe, "codigo do jogo", "o proprio Ragexe") {
        marcas.push(m);
    }

    // --- 2. o nosso próprio código -----------------------------------------
    if let Some(base_dll) = base_da_nossa_dll() {
        if let Some(m) = marcar_secao_de_codigo(
            base_dll,
            "codigo do RagnaShield",
            "as checagens do proprio RSE",
        ) {
            marcas.push(m);
        }
    }

    // --- 3. os prólogos que sustentam as outras detecções -------------------
    for (modulo, funcao, motivo) in FUNCOES_VIGIADAS {
        if let Some(endereco) = sys::endereco_de(modulo, funcao) {
            if let Some(bytes) = ler_memoria(endereco, BYTES_DE_PROLOGO) {
                marcas.push(Marca {
                    nome: format!("{}!{}", modulo, funcao),
                    e_secao: false,
                    motivo: motivo.to_string(),
                    hash: sha256(&bytes),
                });
            }
        }
    }

    marcas
}

/// Base do módulo desta DLL.
///
/// `GetModuleHandleExW` com o endereço de uma função nossa: o Windows devolve
/// qual módulo contém aquele endereço. É o jeito de a DLL descobrir onde ela
/// mesma foi carregada sem depender de saber o próprio nome de arquivo — que o
/// jogador pode ter renomeado.
#[cfg(windows)]
fn base_da_nossa_dll() -> Option<usize> {
    use winapi::um::libloaderapi::{
        GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };

    let mut h: winapi::shared::minwindef::HMODULE = std::ptr::null_mut();
    // SAFETY: passamos o endereço de uma função deste módulo; a flag
    // UNCHANGED_REFCOUNT evita segurar uma referência que nunca soltaríamos.
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            base_da_nossa_dll as *const u16,
            &mut h,
        )
    };
    if ok == 0 || h.is_null() {
        None
    } else {
        Some(h as usize)
    }
}

/// Acha a seção de código de um módulo carregado e resume o conteúdo dela.
#[cfg(windows)]
fn marcar_secao_de_codigo(base: usize, nome: &str, motivo: &str) -> Option<Marca> {
    let (inicio, tamanho) = secao_de_codigo(base)?;
    let bytes = ler_memoria(inicio, tamanho)?;
    Some(Marca {
        nome: nome.to_string(),
        e_secao: true,
        motivo: motivo.to_string(),
        hash: sha256(&bytes),
    })
}

/// Percorre os cabeçalhos PE de um módulo já carregado para achar a seção
/// executável.
///
/// # Por que ler o cabeçalho em vez de fixar um offset
///
/// A seção de código nem sempre se chama `.text` — compiladores e packers usam
/// `CODE`, `.code`, nomes gerados. O que não muda é a **característica**
/// `IMAGE_SCN_MEM_EXECUTE` no descritor da seção. Procurar pela característica
/// funciona em qualquer binário; procurar pelo nome funciona só nos que a gente
/// já viu.
///
/// # SAFETY
///
/// `base` tem que ser a base de um módulo carregado (de `GetModuleHandle*`).
/// Todas as leituras conferem as assinaturas `MZ` e `PE\0\0` antes de andar, e
/// param no primeiro campo que não fizer sentido.
#[cfg(windows)]
fn secao_de_codigo(base: usize) -> Option<(usize, usize)> {
    const ASSINATURA_DOS: u16 = 0x5A4D; // "MZ"
    const ASSINATURA_NT: u32 = 0x0000_4550; // "PE\0\0"
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    /// Offset de `e_lfanew` dentro do cabeçalho DOS.
    const OFF_LFANEW: usize = 0x3C;
    /// Do início do `IMAGE_NT_HEADERS` até o `IMAGE_FILE_HEADER`.
    const OFF_FILE_HEADER: usize = 4;
    /// Dentro do `IMAGE_FILE_HEADER`.
    const OFF_NUM_SECOES: usize = 2;
    const OFF_TAM_OPCIONAL: usize = 16;
    const TAM_FILE_HEADER: usize = 20;
    /// Dentro de cada `IMAGE_SECTION_HEADER` (40 bytes cada).
    const TAM_SECAO: usize = 40;
    const OFF_TAM_VIRTUAL: usize = 8;
    const OFF_ENDERECO_VIRTUAL: usize = 12;
    const OFF_CARACTERISTICAS: usize = 36;

    // SAFETY: leituras não alinhadas dentro de um módulo mapeado, todas
    // guardadas pelas assinaturas conferidas abaixo.
    unsafe {
        let p = base as *const u8;
        if (p as *const u16).read_unaligned() != ASSINATURA_DOS {
            return None;
        }
        let lfanew = (p.add(OFF_LFANEW) as *const u32).read_unaligned() as usize;
        // Um `e_lfanew` absurdo é a forma clássica de PE malformado levar um
        // leitor ingênuo a passear pela memória.
        if lfanew < 0x40 || lfanew > 0x1000 {
            return None;
        }
        let nt = p.add(lfanew);
        if (nt as *const u32).read_unaligned() != ASSINATURA_NT {
            return None;
        }

        let fh = nt.add(OFF_FILE_HEADER);
        let num_secoes = (fh.add(OFF_NUM_SECOES) as *const u16).read_unaligned() as usize;
        let tam_opcional = (fh.add(OFF_TAM_OPCIONAL) as *const u16).read_unaligned() as usize;
        if num_secoes == 0 || num_secoes > 96 {
            return None;
        }

        let secoes = fh.add(TAM_FILE_HEADER + tam_opcional);
        for i in 0..num_secoes {
            let s = secoes.add(i * TAM_SECAO);
            let carac = (s.add(OFF_CARACTERISTICAS) as *const u32).read_unaligned();
            if carac & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            let rva = (s.add(OFF_ENDERECO_VIRTUAL) as *const u32).read_unaligned() as usize;
            let tam = (s.add(OFF_TAM_VIRTUAL) as *const u32).read_unaligned() as usize;
            if rva == 0 || tam == 0 || tam > 512 * 1024 * 1024 {
                continue;
            }
            return Some((base + rva, tam));
        }
        None
    }
}

/// Copia uma região da nossa própria memória, conferindo antes se ela é legível.
///
/// # Por que consultar antes de ler
///
/// Uma seção pode ter páginas não comprometidas no fim, e ler direto ali seria
/// uma falha de página — que num processo de jogo é o jogo fechando, não uma
/// mensagem de erro. `VirtualQuery` responde de graça se a região está
/// comprometida e legível.
#[cfg(windows)]
fn ler_memoria(endereco: usize, tamanho: usize) -> Option<Vec<u8>> {
    use winapi::um::memoryapi::VirtualQuery;
    use winapi::um::winnt::{
        MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
        PAGE_READWRITE, PAGE_WRITECOPY,
    };

    if tamanho == 0 {
        return None;
    }

    // SAFETY: MEMORY_BASIC_INFORMATION é POD; a API a preenche.
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: consulta sobre a nossa própria memória; `info` tem o tamanho declarado.
    let n = unsafe {
        VirtualQuery(
            endereco as *const winapi::ctypes::c_void,
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if n == 0 || info.State != MEM_COMMIT {
        return None;
    }
    if info.Protect & PAGE_GUARD != 0 || info.Protect & PAGE_NOACCESS != 0 {
        return None;
    }
    let legivel = PAGE_READONLY
        | PAGE_READWRITE
        | PAGE_WRITECOPY
        | PAGE_EXECUTE
        | PAGE_EXECUTE_READ
        | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY;
    if info.Protect & legivel == 0 {
        return None;
    }

    // Não passamos do fim da região que a consulta confirmou — o resto pode
    // estar sob outra proteção.
    let disponivel = (info.BaseAddress as usize + info.RegionSize).saturating_sub(endereco);
    let quanto = tamanho.min(disponivel);
    if quanto == 0 {
        return None;
    }

    let mut buf = vec![0u8; quanto];
    // SAFETY: a região foi confirmada comprometida e legível logo acima, e
    // `quanto` não passa do fim dela.
    unsafe {
        std::ptr::copy_nonoverlapping(endereco as *const u8, buf.as_mut_ptr(), quanto);
    }
    Some(buf)
}

/// Registra no log local o que entrou na vigilância — nomes e tamanhos.
#[cfg(windows)]
pub fn registrar_base(base: &[Marca]) {
    for m in base {
        sys::log_dll(&format!(
            "codigo: vigiando {} ({})",
            m.nome,
            if m.e_secao { "secao" } else { "prologo" }
        ));
    }
}

// ===========================================================================
//  Testes da decisão
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn marca(nome: &str, e_secao: bool, semente: u8) -> Marca {
        Marca {
            nome: nome.to_string(),
            e_secao,
            motivo: "motivo".to_string(),
            hash: [semente; 32],
        }
    }

    #[test]
    fn nada_mudou_nao_acusa() {
        let base = vec![marca("codigo do jogo", true, 1), marca("ntdll.dll!X", false, 2)];
        assert!(comparar(&base, &base).is_empty());
    }

    #[test]
    fn codigo_do_jogo_alterado_e_critico() {
        let base = vec![marca("codigo do jogo", true, 1)];
        let agora = vec![marca("codigo do jogo", true, 9)];
        let l = comparar(&base, &agora);
        assert_eq!(l.len(), 1);
        assert!(l[0].starts_with("3002|critica|"), "{}", l[0]);
        assert!(l[0].contains("codigo do jogo"));
    }

    #[test]
    fn prologo_desviado_e_hook() {
        let base = vec![marca("kernel32.dll!IsDebuggerPresent", false, 1)];
        let agora = vec![marca("kernel32.dll!IsDebuggerPresent", false, 7)];
        let l = comparar(&base, &agora);
        assert_eq!(l.len(), 1);
        assert!(l[0].starts_with("2003|alta|"), "{}", l[0]);
    }

    /// 🚨 A regra que protege o jogador: não conseguir reler não é violação.
    #[test]
    fn marca_que_sumiu_nao_acusa() {
        let base = vec![marca("codigo do jogo", true, 1), marca("sumiu", false, 2)];
        let agora = vec![marca("codigo do jogo", true, 1)];
        assert!(comparar(&base, &agora).is_empty());
    }

    #[test]
    fn varias_mudancas_geram_varias_linhas() {
        let base = vec![
            marca("codigo do jogo", true, 1),
            marca("codigo do RagnaShield", true, 2),
            marca("kernel32.dll!GetTickCount64", false, 3),
        ];
        let agora = vec![
            marca("codigo do jogo", true, 11),
            marca("codigo do RagnaShield", true, 2),
            marca("kernel32.dll!GetTickCount64", false, 33),
        ];
        let l = comparar(&base, &agora);
        assert_eq!(l.len(), 2);
        assert!(l.iter().any(|x| x.starts_with("3002|")));
        assert!(l.iter().any(|x| x.starts_with("2003|")));
    }

    /// O separador de campo não pode vazar para o detalhe, senão o Loader
    /// quebra a linha no lugar errado.
    #[test]
    fn as_linhas_tem_exatamente_dois_separadores() {
        let base = vec![marca("codigo do jogo", true, 1)];
        let agora = vec![marca("codigo do jogo", true, 2)];
        for l in comparar(&base, &agora) {
            assert_eq!(l.matches('|').count(), 2, "{}", l);
        }
        assert_eq!(linha_da_base(&base).matches('|').count(), 2);
    }

    #[test]
    fn a_linha_da_base_conta_secoes_e_funcoes() {
        let base = vec![
            marca("a", true, 1),
            marca("b", true, 2),
            marca("c", false, 3),
        ];
        let l = linha_da_base(&base);
        assert!(l.starts_with("6060|info|"), "{}", l);
        assert!(l.contains("2 secao"), "{}", l);
        assert!(l.contains("1 funcao"), "{}", l);
    }
}
