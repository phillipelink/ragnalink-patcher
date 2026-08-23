//! Fase 6.3 — **speedhack de relógio** (`3004`).
//!
//! # O cheat, e por que ele é o mais usado em RO
//!
//! O cliente do Ragnarok decide quase tudo por tempo: quando o cast acaba,
//! quando o próximo ataque libera, quando o personagem dá o próximo passo. E ele
//! pergunta as horas ao Windows.
//!
//! O speedhack do Cheat Engine não acelera o computador — ele **engancha as
//! funções de tempo** dentro do processo do jogo e devolve valores que correm
//! mais rápido. Para o cliente, meio segundo virou dois. Resultado: cast
//! instantâneo, andar acelerado, farm em velocidade de rajada.
//!
//! É o cheat que o pessoal lembra do "linkz" e afins: não é mira nem visão de
//! mapa, é **tempo**.
//!
//! # Como se pega, sem depender de nome nem de assinatura
//!
//! O Windows oferece mais de uma fonte de tempo, e elas vêm de lugares
//! diferentes do sistema:
//!
//! | Fonte | De onde vem |
//! |---|---|
//! | `QueryPerformanceCounter` | contador de alta resolução do hardware |
//! | `GetTickCount64` | contador de milissegundos desde o boot |
//! | `NtGetTickCount` (via `KUSER_SHARED_DATA`) | **página de memória do kernel**, lida direto |
//!
//! Em máquina honesta as três andam **juntas**. Um speedhack precisa enganchar
//! cada uma delas para ser consistente — e é aqui que ele escorrega: a terceira
//! não é uma função, é uma **leitura de memória** num endereço fixo mapeado pelo
//! kernel (`0x7FFE0000`). Não há função para enganchar. Para falsear aquilo, o
//! cheat precisaria de driver.
//!
//! Então medimos: se `QPC` diz que passaram 6 segundos e a página do kernel diz
//! que passaram 2, alguém está mentindo — e sabemos qual dos dois é o mentiroso,
//! porque um deles não pode ser enganchado de modo usuário.
//!
//! # 🚨 Por que a razão, e não a diferença
//!
//! Comparar "quantos ms de diferença" seria frágil: uma máquina travando, um
//! `Alt+Tab`, um swap de disco — tudo isso atrasa o processo e cria diferença.
//!
//! A **razão** entre as duas medidas é estável mesmo assim: se o processo
//! congelou 3 s, as duas fontes congelam junto, e a razão continua ≈ 1,0. Só
//! algo que altere *uma* das fontes muda a razão. É a diferença entre medir
//! "o computador está lento" e medir "alguém mexeu no relógio".
//!
//! # O que isto não pega
//!
//! * **Driver de kernel** que altere a própria `KUSER_SHARED_DATA`. Limite
//!   declarado do RSE_SPEC §2, como sempre.
//! * **Speedhack por injeção de input** (macro que só clica mais rápido) — isso
//!   não mexe no tempo, e quem barra é o `min_skill_delay_limit` do emulador.
//! * Um cheat que acelere de forma **sutil** (1.05×) leva mais tempo para sair
//!   da margem. É de propósito: a margem existe para não acusar máquina ruim.

// Declarado SEM `#![cfg(windows)]` de propósito, igual ao `modulos.rs`.
//
// A parte que **decide** — comparar duas medidas de tempo e dizer se divergiram
// — é aritmética pura, e roda em qualquer máquina. Só as duas leituras de
// relógio precisam do Windows. Separar assim é o que permite testar a decisão
// aqui mesmo, com números escolhidos a dedo, em vez de depender de conseguir um
// speedhack de verdade.
//
// Vale registrar por que isso importa nesta detecção em particular: das cinco
// da Fase 6, esta é a única cuja ameaça não dá para simular de forma honesta.
// As outras têm ferramenta de teste (`testdbg`, `testproc`, `testhandle`) que
// finge ser a ameaça sem ser uma. Aqui, "fingir ser a ameaça" seria escrever um
// speedhack — e a alternativa, baixar um pronto, coloca malware na máquina que
// guarda as chaves do servidor. Então a prova é feita onde dá: na lógica.

#[cfg(windows)]
use crate::sys;

/// `3004 CLOCK_TAMPERED` — as fontes de tempo do processo discordam.
///
/// Faixa 3000–3999 (ambiente do processo), vizinha do `3001 DEBUGGER_ATTACHED`.
/// O registro dos códigos fica em `rse/docs/CODIGOS.md`.
const COD_RELOGIO: u16 = 3004;

/// Faixa experimental: a razão medida, para calibrar a margem com dados reais
/// antes de mexer nela no escuro.
const COD_RELOGIO_MEDIDO: u16 = 6050;

/// Quanto as fontes podem divergir antes de virar acusação.
///
/// Uma máquina honesta fica em 1.00 ± 0.02 mesmo sob carga, porque as duas
/// fontes param juntas. A folga aqui é generosa de propósito: o speedhack que
/// vale a pena usar num MMO é de 2× a 5×, não de 1.2× — então dá para ser
/// tolerante sem perder o que interessa.
///
/// Acusar jogador honesto por causa de uma máquina engasgando custa muito mais
/// caro do que deixar passar um trapaceiro tímido.
const RAZAO_MIN: f64 = 0.80;
const RAZAO_MAX: f64 = 1.25;

/// Quanto tempo precisa passar antes de uma medida valer.
///
/// Medir intervalos curtos amplifica ruído: 10 ms de atraso em 100 ms é 10% de
/// erro; em 10 s é 0,1%. Esperamos acumular tempo suficiente para a razão ser
/// significativa.
const JANELA_MINIMA_MS: u64 = 5_000;

/// Quanto a nossa leitura da página do kernel pode divergir do `GetTickCount64`
/// na autoconferência do arranque.
///
/// As duas leem a MESMA página, então em teoria batem exatamente. A folga cobre
/// o tempo entre as duas chamadas e a granularidade do tique (~15,6 ms). Passar
/// muito disso significa que estamos lendo a estrutura errada.
const TOLERANCIA_AUTOCONFERENCIA_MS: i64 = 100;

/// Endereço fixo da `KUSER_SHARED_DATA` — página que o kernel mapeia, somente
/// leitura, em **todo** processo do Windows, desde o NT.
///
/// Não é um truque obscuro: é documentado, e é onde o próprio `GetTickCount` do
/// kernel32 vai buscar o valor. A graça de ler daqui é justamente pular a
/// função: não existe ponto para enganchar numa leitura de memória.
const KUSER_SHARED_DATA: usize = 0x7FFE_0000;
/// Offset do `TickCountMultiplier` dentro da página.
const OFF_TICK_MULT: usize = 0x004;
/// Offset da estrutura `TickCount` (`LowPart`, `High1Time`, `High2Time`).
const OFF_TICK_COUNT: usize = 0x320;

/// O que a comparação das duas fontes concluiu.
#[derive(Debug, PartialEq)]
pub enum Veredito {
    /// Ainda não passou tempo suficiente para a razão significar algo.
    CedoDemais,
    /// As duas fontes andam juntas. `f64` = a razão medida.
    Normal(f64),
    /// Divergiram além da margem. `f64` = a razão medida.
    Divergente(f64),
}

/// Julga duas medidas de tempo decorrido. **Função pura** — é aqui que a
/// detecção realmente decide, e é isto que os testes exercitam.
///
/// `qpc_ms` vem do contador de alta resolução (engancháve1 por speedhack);
/// `kernel_ms` vem da página do kernel (não engancháve1 sem driver).
pub fn julgar(qpc_ms: f64, kernel_ms: u64) -> Veredito {
    if kernel_ms < JANELA_MINIMA_MS {
        return Veredito::CedoDemais;
    }
    let razao = qpc_ms / kernel_ms as f64;
    if (RAZAO_MIN..=RAZAO_MAX).contains(&razao) {
        Veredito::Normal(razao)
    } else {
        Veredito::Divergente(razao)
    }
}

/// Traduz um veredito de divergência em linhas de REPORT.
pub fn linhas_de_report(razao: f64, qpc_ms: f64, kernel_ms: u64) -> Vec<String> {
    vec![
        format!(
            "{}|critica|relogio adulterado: QPC andou {:.0} ms enquanto o kernel andou {} ms (razao {:.2})",
            COD_RELOGIO, qpc_ms, kernel_ms, razao
        ),
        format!("{}|info|razao de relogio medida: {:.3}", COD_RELOGIO_MEDIDO, razao),
    ]
}

/// Estado da medição entre varreduras. Só existe no Windows — guarda leituras
/// de relógio do sistema. A decisão sobre elas (`julgar`) é pura e mora acima.
#[cfg(windows)]
pub struct Relogio {
    qpc_freq: i64,
    qpc_inicial: i64,
    kernel_inicial: u64,
    /// Já reportamos nesta sessão? Relatamos a transição, não o estado — um
    /// speedhack ligado a tarde toda geraria um relatório por minuto.
    acusado: bool,
}

#[cfg(windows)]
impl Relogio {
    /// `None` = não conseguimos medir nesta máquina (QPC indisponível). Nunca
    /// chuta: sem base de comparação, não há detecção, e dizer "limpo" seria
    /// mentir.
    pub fn novo() -> Option<Relogio> {
        let freq = qpc_frequencia()?;
        if freq <= 0 {
            return None;
        }
        let qpc = qpc_contador()?;
        let kernel = tick_do_kernel()?;

        // --- autoconferência: a nossa leitura da página do kernel está certa? --
        //
        // `GetTickCount64` lê exatamente a mesma `KUSER_SHARED_DATA` que nós,
        // só que passando pela função do kernel32. Se a nossa leitura manual
        // estiver certa, os dois valores batem quase exatamente.
        //
        // Isto existe por causa da lição da 6.4b: lá, uma leitura de estrutura
        // do sistema saiu errada e a detecção passou meses de trabalho parecendo
        // funcionar enquanto media a coisa errada. Uma detecção baseada em
        // leitura crua de memória **precisa** provar que sabe ler antes de ter
        // permissão de acusar alguém.
        //
        // A conferência é feita UMA vez, no arranque — o momento em que ainda
        // não há speedhack nenhum instalado. Fazê-la a cada varredura seria um
        // presente para o cheat: bastaria enganchar o `GetTickCount64` para a
        // conferência falhar e a detecção se desligar sozinha.
        // SAFETY: sem parâmetros, não falha.
        let pelo_kernel32 = unsafe { winapi::um::sysinfoapi::GetTickCount64() };
        let diferenca = (pelo_kernel32 as i64 - kernel as i64).abs();
        if diferenca > TOLERANCIA_AUTOCONFERENCIA_MS {
            sys::log_dll(&format!(
                "relogio: autoconferencia FALHOU (kernel32={} nossa_leitura={} dif={} ms). \
                 Nao vou acusar ninguem com base numa leitura que nao sei fazer.",
                pelo_kernel32, kernel, diferenca
            ));
            return None;
        }

        sys::log_dll(&format!(
            "relogio: base QPC={} kernel={} freq={} (autoconferencia ok, dif={} ms)",
            qpc, kernel, freq, diferenca
        ));
        Some(Relogio {
            qpc_freq: freq,
            qpc_inicial: qpc,
            kernel_inicial: kernel,
            acusado: false,
        })
    }
}

/// Compara as duas fontes e devolve as linhas de REPORT.
///
/// Devolve vazio quando ainda não há janela suficiente, quando tudo bate, ou
/// quando já acusamos nesta sessão.
#[cfg(windows)]
pub fn verificar(r: &mut Relogio) -> Vec<String> {
    let (qpc, kernel) = match (qpc_contador(), tick_do_kernel()) {
        (Some(a), Some(b)) => (a, b),
        _ => return Vec::new(), // não sei: não acusa
    };

    let kernel_ms = kernel.saturating_sub(r.kernel_inicial);
    let ticks = qpc.saturating_sub(r.qpc_inicial);
    let qpc_ms = (ticks as f64 * 1000.0) / r.qpc_freq as f64;

    match julgar(qpc_ms, kernel_ms) {
        Veredito::CedoDemais => Vec::new(),

        Veredito::Normal(razao) => {
            // Registra a razão em toda varredura. É barato, e é o que permite
            // olhar o log de uma máquina real e ver a medida oscilando em torno
            // de 1.000 — a prova de que as duas fontes estão sendo lidas certo,
            // sem precisar de um speedhack de verdade para confiar na detecção.
            sys::log_dll(&format!(
                "relogio: razao={:.4} (qpc={:.0}ms kernel={}ms)",
                razao, qpc_ms, kernel_ms
            ));
            if r.acusado {
                sys::log_dll(&format!("relogio: voltou ao normal (razao {:.3})", razao));
                r.acusado = false;
            }
            Vec::new()
        }

        Veredito::Divergente(razao) => {
            if r.acusado {
                return Vec::new(); // já relatado; espera voltar ao normal
            }
            r.acusado = true;
            sys::log_dll(&format!(
                "relogio: DIVERGENCIA razao={:.3} qpc={:.0}ms kernel={}ms",
                razao, qpc_ms, kernel_ms
            ));
            linhas_de_report(razao, qpc_ms, kernel_ms)
        }
    }
}

// ===========================================================================
//  As duas fontes
// ===========================================================================

#[cfg(windows)]
fn qpc_frequencia() -> Option<i64> {
    use winapi::um::profileapi::QueryPerformanceFrequency;
    let mut v: i64 = 0;
    // SAFETY: `v` é um i64 válido; a API só escreve nele.
    let ok = unsafe { QueryPerformanceFrequency(&mut v as *mut i64 as *mut _) };
    if ok == 0 {
        None
    } else {
        Some(v)
    }
}

#[cfg(windows)]
fn qpc_contador() -> Option<i64> {
    use winapi::um::profileapi::QueryPerformanceCounter;
    let mut v: i64 = 0;
    // SAFETY: idem.
    let ok = unsafe { QueryPerformanceCounter(&mut v as *mut i64 as *mut _) };
    if ok == 0 {
        None
    } else {
        Some(v)
    }
}

/// Lê o tick do kernel direto da `KUSER_SHARED_DATA`, sem passar por função.
///
/// # A leitura em duas etapas, e por que ela não é paranoia
///
/// O `TickCount` é de 64 bits, mas a página é atualizada por um kernel que pode
/// ser de 32 bits — então a escrita não é atômica. A estrutura resolve isso com
/// **dois campos de parte alta**: o kernel escreve `High2Time`, depois
/// `LowPart`, depois `High1Time`. Quem lê confere se as duas partes altas
/// batem; se não baterem, pegou a atualização no meio e tenta de novo.
///
/// Sem esse cuidado, uma leitura a cada ~49,7 dias de uptime (quando o `LowPart`
/// dá a volta) devolveria um valor absurdo — e o absurdo viraria acusação de
/// speedhack contra um inocente.
///
/// # SAFETY
///
/// `KUSER_SHARED_DATA` é mapeada como somente-leitura em todo processo do
/// Windows, num endereço fixo, desde o NT 3.1. A leitura é `read_volatile`
/// porque a página muda por baixo de nós — o compilador não pode presumir que
/// duas leituras devolvem o mesmo.
#[cfg(windows)]
fn tick_do_kernel() -> Option<u64> {
    let base = KUSER_SHARED_DATA as *const u8;
    // SAFETY: ver o comentário acima — endereço fixo, mapeado, somente leitura.
    unsafe {
        let mult = (base.add(OFF_TICK_MULT) as *const u32).read_volatile() as u64;
        if mult == 0 {
            return None; // página não é o que esperávamos; não inventa
        }
        let p = base.add(OFF_TICK_COUNT);
        for _ in 0..8 {
            let alto2 = (p.add(8) as *const u32).read_volatile();
            let baixo = (p as *const u32).read_volatile() as u64;
            let alto1 = (p.add(4) as *const u32).read_volatile();
            if alto1 == alto2 {
                let bruto = (alto1 as u64) << 32 | baixo;
                // O valor cru é em unidades do timer; o multiplicador o converte
                // em milissegundos. É a mesma conta que o GetTickCount faz.
                return Some((bruto * mult) >> 24);
            }
        }
        None // oito tentativas sem leitura estável: desiste em vez de chutar
    }
}

// ===========================================================================
//  Testes da decisão
// ===========================================================================
//
// Estes testes são o substituto honesto de "baixar um speedhack e ver se
// acende". Eles não provam que o Cheat Engine causa divergência — isso é
// consequência conhecida de como o speedhack funciona, e está explicado no
// cabeçalho. O que eles provam é o resto: **dada** a divergência, a detecção
// acusa; e dado o comportamento de uma máquina honesta (inclusive travando),
// ela não acusa.
//
// Os números de "speedhack" abaixo saem direto do multiplicador do Cheat
// Engine: em 2×, o QPC enganchado anda o dobro enquanto o relógio do kernel
// anda o normal.

#[cfg(test)]
mod tests {
    use super::*;

    /// 30 s de relógio de kernel — a janela típica entre varreduras.
    const JANELA: u64 = 30_000;

    #[test]
    fn maquina_honesta_nao_acusa() {
        // O caso medido em campo: 30067 ms de QPC contra 30062 do kernel.
        match julgar(30_067.0, 30_062) {
            Veredito::Normal(r) => assert!((r - 1.0).abs() < 0.01, "razao {}", r),
            outro => panic!("acusou maquina honesta: {:?}", outro),
        }
    }

    #[test]
    fn speedhack_de_2x_acusa() {
        // QPC enganchado andando o dobro.
        match julgar(JANELA as f64 * 2.0, JANELA) {
            Veredito::Divergente(r) => assert!((r - 2.0).abs() < 0.01, "razao {}", r),
            outro => panic!("deixou passar speedhack 2x: {:?}", outro),
        }
    }

    #[test]
    fn speedhack_de_5x_acusa() {
        match julgar(JANELA as f64 * 5.0, JANELA) {
            Veredito::Divergente(_) => {}
            outro => panic!("deixou passar speedhack 5x: {:?}", outro),
        }
    }

    /// Slowmotion é o mesmo cheat com o multiplicador invertido — usado para
    /// esticar janelas de reação. A margem tem que pegar os dois lados.
    #[test]
    fn slowhack_de_meio_x_acusa() {
        match julgar(JANELA as f64 * 0.5, JANELA) {
            Veredito::Divergente(_) => {}
            outro => panic!("deixou passar slowhack 0.5x: {:?}", outro),
        }
    }

    /// 🚨 O teste que protege o jogador honesto.
    ///
    /// Uma máquina engasgando, um Alt+Tab, um swap de disco: o processo inteiro
    /// congela, e **as duas fontes congelam junto**. A razão não se mexe. É por
    /// isso que a detecção usa razão e não diferença — e é isto que garante que
    /// PC ruim não vira acusação.
    #[test]
    fn travamento_do_pc_nao_acusa() {
        for congelado_ms in [1_000u64, 5_000, 15_000, 60_000] {
            // As duas medidas perdem o mesmo tempo.
            let qpc = (JANELA - congelado_ms.min(JANELA - 1)) as f64;
            let kernel = JANELA - congelado_ms.min(JANELA - 1);
            match julgar(qpc, kernel) {
                Veredito::Normal(_) | Veredito::CedoDemais => {}
                outro => panic!("acusou por travamento de {} ms: {:?}", congelado_ms, outro),
            }
        }
    }

    /// Deriva pequena de cristal entre as duas fontes não pode acusar. 2% é bem
    /// acima do que hardware real produz.
    #[test]
    fn deriva_pequena_nao_acusa() {
        for fator in [0.98f64, 0.99, 1.01, 1.02, 1.05, 1.10] {
            match julgar(JANELA as f64 * fator, JANELA) {
                Veredito::Normal(_) => {}
                outro => panic!("acusou por deriva de {}x: {:?}", fator, outro),
            }
        }
    }

    #[test]
    fn janela_curta_nao_julga() {
        // Mesmo com divergência absurda, medida curta demais não acusa: 10 ms de
        // ruído em 100 ms de janela seriam 10% de erro por nada.
        assert_eq!(julgar(9_999.0, 1_000), Veredito::CedoDemais);
    }

    /// As bordas exatas da margem. É o tipo de detalhe que muda em silêncio
    /// quando alguém mexe nas constantes sem perceber.
    #[test]
    fn bordas_da_margem() {
        let k = JANELA;
        assert!(matches!(julgar(k as f64 * RAZAO_MAX, k), Veredito::Normal(_)));
        assert!(matches!(julgar(k as f64 * RAZAO_MIN, k), Veredito::Normal(_)));
        assert!(matches!(
            julgar(k as f64 * (RAZAO_MAX + 0.01), k),
            Veredito::Divergente(_)
        ));
        assert!(matches!(
            julgar(k as f64 * (RAZAO_MIN - 0.01), k),
            Veredito::Divergente(_)
        ));
    }

    #[test]
    fn o_relato_traz_o_codigo_e_a_severidade_certos() {
        let linhas = linhas_de_report(2.0, 60_000.0, 30_000);
        assert!(linhas[0].starts_with("3004|critica|"), "{}", linhas[0]);
        assert!(linhas[1].starts_with("6050|info|"), "{}", linhas[1]);
        // O separador de campo não pode aparecer no detalhe, senão o Loader
        // quebra a linha no lugar errado.
        for l in &linhas {
            assert_eq!(l.matches('|').count(), 2, "pipes demais em: {}", l);
        }
    }
}
