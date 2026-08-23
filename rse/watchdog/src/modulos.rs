//! Fase 6.2 — **módulos carregados** dentro do cliente.
//!
//! # A pergunta certa não é *qual* DLL, é *como ela chegou aqui*
//!
//! O reflexo, ao ler "detectar DLL de cheat", é fazer uma **lista de nomes
//! proibidos**. Não vale a pena, e é importante entender por quê antes de ler o
//! resto do arquivo: o sujeito renomeia o arquivo e a lista inteira vira enfeite.
//! Uma lista de nomes só pega quem não tentou nada — e custa manutenção eterna,
//! porque toda variante nova exige uma linha nova.
//!
//! O que **não** é fácil de disfarçar é a *procedência*. Uma DLL legítima do
//! cliente mora na pasta do jogo. Uma DLL legítima do Windows mora em
//! `C:\Windows`. Uma DLL injetada mora onde o injetor a deixou — muito
//! frequentemente `%TEMP%`, Downloads ou a Área de Trabalho — e **aparece depois
//! que o processo já começou**. São essas duas propriedades que este módulo mede,
//! e elas não dependem de conhecer cheat nenhum pelo nome.
//!
//! Por isso o `2001 KNOWN_CHEAT_MODULE` do RSE_SPEC §9 **fica sem implementação
//! por enquanto**, de propósito. Se um dia aparecer uma família específica em
//! campo, aí sim vale uma regra dedicada — com o nome vindo de telemetria real,
//! não de palpite.
//!
//! # A linha de base sai de graça, e é o melhor momento possível
//!
//! O RSE já tem um instante privilegiado: o `apertar_mao`, quando o jogo ainda
//! está **suspenso** (o Loader só dá `ResumeThread` depois do `HELLO_ACK`). Nesse
//! ponto a lista de módulos é só o que o `.exe` importa estaticamente, mais a
//! nossa DLL. É a fotografia mais limpa que existe deste processo — e é a mesma
//! janela que a integridade já usa para conseguir ler a `data.grf`.
//!
//! Tudo que aparecer **depois** disso é carregamento em tempo de execução: pode
//! ser legítimo (D3D, codecs, IME, overlay do Discord/Steam) ou pode ser injeção.
//! A origem do arquivo é o que separa os dois casos.
//!
//! # 🚨 O que este módulo NÃO vê — dito na cara
//!
//! 1. **Manual mapping.** Um cheat sério não chama `LoadLibrary`: ele copia a DLL
//!    para a memória do processo na mão e conserta as relocações. O módulo então
//!    **nunca entra na lista do carregador do Windows**, e nada aqui o enxerga.
//!    Pegar isso exige varrer regiões de memória executáveis sem módulo por trás
//!    — outro trabalho, com outro perfil de falso-positivo.
//! 2. **DLL que já estava lá antes da linha de base** (`AppInit_DLLs`, import
//!    adulterado no próprio `.exe`). Ela entra na foto como se fosse normal.
//!    Mitigação parcial: o inventário do arranque relata **quem já estava lá e
//!    veio de fora** das pastas conhecidas — então uma DLL estranha presente desde
//!    o início continua aparecendo, só que rotulada como "presente no arranque"
//!    em vez de "carregada depois".
//!
//! Nenhuma das duas é motivo para não fazer o barato primeiro. É motivo para não
//! dizer ao operador que o cliente está limpo quando o que se sabe é menos.
//!
//! # Falso-positivo é a regra aqui, não a exceção
//!
//! Injetar DLL em jogo é coisa que **software legítimo faz o tempo todo**:
//! overlay do Discord e do Steam, MSI Afterburner/RivaTuner, OBS, Nahimic,
//! antivírus. Todos vão acender esta detecção. **Isso é esperado e é o objetivo
//! da primeira rodada**: descobrir como é o "normal" da sua base antes de
//! transformar qualquer coisa disso em ação.
//!
//! Por isso tudo aqui é **report puro**, nunca `kill` — a ação vem do
//! `REPORT_ACK`, como manda o §9 (*severidade não é ação*). E a severidade separa
//! o que merece o olho do operador: uma DLL vinda de `%TEMP%` é `alta`; uma vinda
//! de `Arquivos de Programas` é `media`, porque quase sempre é overlay.
//!
//! # Privacidade
//!
//! Caminho de módulo contém o **nome de usuário do Windows**
//! (`C:\Users\Fulano\...`), e o RSE_SPEC §8 diz explicitamente que nome de usuário
//! **não sai da máquina do jogador**. Todo caminho passa por `redigir_usuario`
//! antes de virar linha de relato. O que interessa ao diagnóstico é a *pasta*, não
//! quem é a pessoa.

#![allow(dead_code)] // as partes puras existem para os testes rodarem fora do Windows

/// `2000 UNKNOWN_MODULE_LOADED` — RSE_SPEC §9.
const COD_MODULO_DESCONHECIDO: u16 = 2000;
/// Faixa experimental (6000–6999): inventário do arranque, telemetria pura.
const COD_INVENTARIO: u16 = 6020;

/// Teto de linhas por relato.
///
/// O frame do canal aceita 8192 bytes de payload. Uma máquina com muito overlay
/// poderia gerar dezenas de linhas de uma vez e estourar isso — e, pior, afogar
/// o log do servidor. Cortamos em 12 e **dizemos quantas ficaram de fora**:
/// relatório truncado em silêncio faz o operador achar que viu tudo.
const MAX_LINHAS: usize = 12;

/// De onde o arquivo do módulo veio. É isto que decide se relatamos, e com que
/// severidade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origem {
    /// Debaixo de `C:\Windows` — System32, SysWOW64, WinSxS…
    Sistema,
    /// Debaixo da pasta do jogo.
    Jogo,
    /// Instalado em outro lugar normal (Arquivos de Programas e afins).
    /// Quase sempre overlay ou antivírus.
    Instalado,
    /// Pasta volátil — `%TEMP%`, Downloads, Área de Trabalho, `Users\Public`.
    /// É onde injetor deixa arquivo.
    Volatil,
    /// Caminho vazio, ou arquivo que **não existe** no caminho declarado.
    /// Injetor que apaga o arquivo depois de carregar cai aqui.
    Fantasma,
}

impl Origem {
    /// Módulo de origem conhecida não vira relato. Sem isto, cada varredura
    /// despejaria a lista inteira do Windows.
    pub fn suspeita(self) -> bool {
        !matches!(self, Origem::Sistema | Origem::Jogo)
    }

    fn severidade(self) -> &'static str {
        match self {
            // Arquivo em pasta volátil ou que sumiu do disco: é o formato de
            // injeção, não de instalação.
            Origem::Volatil | Origem::Fantasma => "alta",
            _ => "media",
        }
    }

    fn rotulo(self) -> &'static str {
        match self {
            Origem::Sistema => "sistema",
            Origem::Jogo => "jogo",
            Origem::Instalado => "instalado",
            Origem::Volatil => "volatil",
            Origem::Fantasma => "fantasma",
        }
    }
}

/// Trechos de caminho que denunciam pasta volátil. Comparados em minúsculas,
/// com as barras já normalizadas.
const MARCAS_VOLATEIS: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\users\\public\\",
];

/// Deixa o caminho comparável: minúsculas e barra invertida.
///
/// O Windows aceita `/` e `\` misturados e não diferencia maiúsculas, então
/// comparar cru daria falso "veio de fora" para um caminho perfeitamente normal
/// escrito de outro jeito.
pub fn normalizar(caminho: &str) -> String {
    caminho.replace('/', "\\").to_lowercase()
}

/// Troca o nome de usuário por `*` em `C:\Users\Fulano\...`.
///
/// Requisito do RSE_SPEC §8, não capricho: nome de usuário do Windows não sai da
/// máquina do jogador. A pasta continua legível para diagnóstico
/// (`C:\Users\*\AppData\Local\Temp\x.dll` diz tudo o que precisamos saber).
pub fn redigir_usuario(caminho: &str) -> String {
    let baixo = normalizar(caminho);
    let marca = "\\users\\";
    let i = match baixo.find(marca) {
        Some(i) => i + marca.len(),
        None => return caminho.to_string(),
    };
    // Fim do nome do usuário = próxima barra, ou o fim da string.
    // (Padrão como fatia de `char`, e não `['\\','/']`: o array só virou Pattern
    // no Rust 1.71, e a toolchain do projeto está travada em 1.68.2.)
    let fim = match caminho[i..].find(&['\\', '/'][..]) {
        Some(j) => i + j,
        None => caminho.len(),
    };
    if fim <= i {
        return caminho.to_string(); // `\Users\` sem nome: nada a redigir
    }
    format!("{}*{}", &caminho[..i], &caminho[fim..])
}

/// Decide a origem de um caminho de módulo.
///
/// `existe` é o que o disco respondeu: `Some(true)` achou, `Some(false)` **não**
/// achou, `None` = "não sei" (acesso negado, disco removido). O `None` nunca vira
/// acusação — é a mesma regra do 6.1: *não sei ≠ não tem*, e aqui *não sei ≠ é
/// fantasma*.
///
/// A ordem das checagens não é arbitrária:
///
/// 1. **Jogo e Sistema primeiro.** Se alguém descompactou o cliente dentro de
///    `Downloads`, toda DLL do próprio jogo casaria com uma marca volátil e a
///    detecção viraria um despejo de ruído já na primeira varredura. A pasta do
///    jogo ganha da marca volátil de propósito.
/// 2. **Fantasma antes de volátil**, porque é o sinal mais forte dos dois.
pub fn classificar(
    caminho: &str,
    pasta_windows: &str,
    pasta_jogo: &str,
    existe: Option<bool>,
) -> Origem {
    let c = normalizar(caminho);
    if c.trim().is_empty() {
        return Origem::Fantasma;
    }
    if !pasta_jogo.is_empty() && c.starts_with(&normalizar(pasta_jogo)) {
        return Origem::Jogo;
    }
    if !pasta_windows.is_empty() && c.starts_with(&normalizar(pasta_windows)) {
        return Origem::Sistema;
    }
    if existe == Some(false) {
        return Origem::Fantasma;
    }
    if MARCAS_VOLATEIS.iter().any(|m| c.contains(m)) {
        return Origem::Volatil;
    }
    Origem::Instalado
}

/// Um módulo como a foto o viu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modulo {
    pub nome: String,
    pub caminho: String,
}

/// Monta as linhas do relato a partir de módulos suspeitos.
///
/// `depois_do_arranque` separa os dois casos, que **têm peso diferente**: um
/// módulo que apareceu com o jogador jogando é evento; um que já estava lá no
/// arranque é inventário. Misturar os dois faria o operador tratar overlay de
/// Discord com a mesma urgência de uma DLL que entrou no meio da partida.
pub fn linhas(
    suspeitos: &[(Modulo, Origem)],
    depois_do_arranque: bool,
    total_modulos: usize,
) -> Vec<String> {
    let mut v = Vec::new();

    if !depois_do_arranque {
        // Uma linha de resumo, sempre — mesmo com zero suspeitos. É ela que
        // constrói a base de comparação: saber que a máquina tinha 74 módulos e
        // nenhum de fora vale tanto quanto saber que tinha três.
        v.push(format!(
            "{}|info|inventario no arranque: {} modulo(s), {} de fora das pastas conhecidas",
            COD_INVENTARIO,
            total_modulos,
            suspeitos.len()
        ));
    }

    let quando = if depois_do_arranque {
        "carregado depois do arranque"
    } else {
        "presente no arranque"
    };

    for (m, origem) in suspeitos.iter().take(MAX_LINHAS) {
        let (codigo, severidade) = if depois_do_arranque {
            (COD_MODULO_DESCONHECIDO, origem.severidade())
        } else {
            // No arranque é telemetria: entra na faixa experimental e em `info`,
            // para não competir no log com o que aconteceu ao vivo.
            (COD_INVENTARIO, "info")
        };
        v.push(format!(
            "{}|{}|{}: {} [{}] {}",
            codigo,
            severidade,
            quando,
            m.nome,
            origem.rotulo(),
            redigir_usuario(&m.caminho)
        ));
    }

    if suspeitos.len() > MAX_LINHAS {
        v.push(format!(
            "{}|info|... e mais {} modulo(s) nao listado(s) (teto de {} por relato)",
            COD_INVENTARIO,
            suspeitos.len() - MAX_LINHAS,
            MAX_LINHAS
        ));
    }
    v
}

// ===========================================================================
//  A vigia — linha de base no arranque, e só o que é novo depois
// ===========================================================================

/// Guarda a foto do arranque e responde "o que apareceu desde então".
///
/// Relata **na transição**, igual à detecção de depurador da 6.1: um módulo já
/// relatado entra na lista de conhecidos e não volta a aparecer. Sem isso, um
/// overlay do Discord geraria a mesma linha a cada 30 s durante horas — e o
/// operador aprenderia a ignorar o canal inteiro.
pub struct Vigia {
    conhecidos: Vec<String>, // caminhos normalizados
    pasta_windows: String,
    pasta_jogo: String,
}

impl Vigia {
    /// Constrói a vigia a partir de uma lista já obtida — a forma testável.
    pub fn a_partir_de(
        foto: Vec<Modulo>,
        pasta_windows: String,
        pasta_jogo: String,
        existe: &dyn Fn(&str) -> Option<bool>,
    ) -> (Vigia, Vec<String>) {
        let total = foto.len();
        let mut conhecidos = Vec::with_capacity(total);
        let mut suspeitos = Vec::new();
        for m in foto {
            let origem = classificar(&m.caminho, &pasta_windows, &pasta_jogo, existe(&m.caminho));
            conhecidos.push(normalizar(&m.caminho));
            if origem.suspeita() {
                suspeitos.push((m, origem));
            }
        }
        let linhas = linhas(&suspeitos, false, total);
        (
            Vigia {
                conhecidos,
                pasta_windows,
                pasta_jogo,
            },
            linhas,
        )
    }

    /// Compara uma foto nova com a linha de base e devolve o relato do que é novo.
    pub fn comparar(
        &mut self,
        foto: Vec<Modulo>,
        existe: &dyn Fn(&str) -> Option<bool>,
    ) -> Vec<String> {
        let total = foto.len();
        let mut suspeitos = Vec::new();
        for m in foto {
            let chave = normalizar(&m.caminho);
            if self.conhecidos.iter().any(|c| *c == chave) {
                continue;
            }
            // Entra em `conhecidos` mesmo quando não é suspeito: um módulo de
            // sistema carregado depois é normal e não queremos reavaliá-lo a cada
            // varredura.
            self.conhecidos.push(chave);
            let origem = classificar(
                &m.caminho,
                &self.pasta_windows,
                &self.pasta_jogo,
                existe(&m.caminho),
            );
            if origem.suspeita() {
                suspeitos.push((m, origem));
            }
        }
        if suspeitos.is_empty() {
            return Vec::new();
        }
        linhas(&suspeitos, true, total)
    }
}

// ===========================================================================
//  A parte que fala com o Windows
// ===========================================================================

#[cfg(windows)]
mod win {
    use super::Modulo;

    use winapi::shared::minwindef::MAX_PATH;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    /// `ERROR_BAD_LENGTH` — a lista de módulos mudou no meio da leitura.
    /// A documentação da Microsoft manda **tentar de novo**, e não é raro: o
    /// arranque de um jogo carrega DLL o tempo todo.
    const ERROR_BAD_LENGTH: u32 = 24;
    const TENTATIVAS: u32 = 4;

    /// Tira a foto dos módulos do **próprio** processo.
    ///
    /// `TH32CS_SNAPMODULE32` junto com `TH32CS_SNAPMODULE` é o que faz um
    /// processo de 32 bits enxergar a própria lista quando o Windows é 64 bits —
    /// e o Ragexe é 32 bits, então isto não é opcional aqui.
    pub fn retrato() -> Result<Vec<Modulo>, String> {
        for tentativa in 0..TENTATIVAS {
            match uma_tentativa() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if e != ERROR_BAD_LENGTH || tentativa + 1 == TENTATIVAS {
                        return Err(format!("CreateToolhelp32Snapshot falhou (erro {})", e));
                    }
                    crate::sys::dormir_ms(50);
                }
            }
        }
        Err("nao consegui tirar a foto dos modulos".to_string())
    }

    /// `Err(codigo)` devolve o erro do Windows para o chamador decidir se repete.
    fn uma_tentativa() -> Result<Vec<Modulo>, u32> {
        // 0 = processo atual. Passar o PID também funcionaria; 0 evita uma
        // chamada e é o que a documentação recomenda para o próprio processo.
        // SAFETY: chamada de API sem ponteiro; o handle é fechado abaixo.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0) };
        if snap == INVALID_HANDLE_VALUE {
            // SAFETY: leitura do último erro da thread.
            return Err(unsafe { GetLastError() });
        }

        // SAFETY: MODULEENTRY32W é POD; `dwSize` é obrigatório antes do primeiro uso.
        let mut e: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        let mut v = Vec::new();
        // SAFETY: `snap` é válido; a API preenche `e` a cada passo.
        unsafe {
            if Module32FirstW(snap, &mut e) != 0 {
                loop {
                    // Os buffers são COPIADOS para locais antes de virar fatia.
                    // Pegar referência a campo de struct do winapi já custou caro
                    // neste projeto uma vez (`NOTIFYICONDATAW` é `packed`, e
                    // `&campo` ali é erro de compilação/UB). Copiar 520 bytes por
                    // módulo, a cada 30 s, não é medível — e a classe inteira de
                    // problema deixa de existir.
                    let nome = e.szModule;
                    let caminho = e.szExePath;
                    v.push(Modulo {
                        nome: texto(&nome),
                        caminho: texto(&caminho),
                    });
                    if Module32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        Ok(v)
    }

    /// UTF-16 terminado em zero -> String.
    fn texto(buf: &[u16]) -> String {
        let fim = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..fim])
    }

    /// `C:\Windows`, perguntado ao sistema em vez de assumido.
    ///
    /// Assumir `C:\Windows` quebraria em instalação fora do C: — rara, mas o
    /// efeito seria classificar **todo o Windows** como módulo suspeito, e o
    /// jogador viraria um despejo de falso-positivo sem nada de errado na máquina.
    pub fn pasta_do_windows() -> String {
        use winapi::um::sysinfoapi::GetWindowsDirectoryW;
        let mut buf = [0u16; MAX_PATH + 1];
        // SAFETY: buffer com o tamanho declarado.
        let n = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 || n as usize > buf.len() {
            return String::new(); // sem isto, não classificamos nada como sistema
        }
        String::from_utf16_lossy(&buf[..n as usize])
    }

    /// A pasta onde o `.exe` do jogo mora.
    pub fn pasta_do_jogo() -> String {
        crate::sys::caminho_do_exe()
            .and_then(|c| {
                std::path::Path::new(&c)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
            })
            .unwrap_or_default()
    }

    /// O arquivo existe? `None` = não deu para saber.
    ///
    /// A distinção importa: acesso negado devolveria `Err` igual a "não existe",
    /// e um módulo perfeitamente legítimo numa pasta protegida viraria
    /// `fantasma` — a severidade mais alta desta detecção, pelo motivo errado.
    pub fn existe(caminho: &str) -> Option<bool> {
        if caminho.trim().is_empty() {
            return Some(false);
        }
        match std::fs::metadata(caminho) {
            Ok(_) => Some(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    }
}

/// Monta a vigia com a foto do arranque. Devolve também as linhas do inventário.
///
/// Falha ao tirar a foto **não** é fatal e não acusa ninguém: devolve `None`, o
/// canal registra o motivo no log da DLL, e a varredura periódica simplesmente
/// não roda. Anti-cheat que trata erro de API como violação cria falso-positivo
/// em máquina esquisita, que é exatamente o jogador que menos consegue explicar
/// o que houve.
#[cfg(windows)]
pub fn iniciar_vigia() -> Result<(Vigia, Vec<String>), String> {
    let foto = win::retrato()?;
    Ok(Vigia::a_partir_de(
        foto,
        win::pasta_do_windows(),
        win::pasta_do_jogo(),
        &win::existe,
    ))
}

/// Uma varredura periódica: devolve o relato do que apareceu desde a última.
#[cfg(windows)]
pub fn varrer(vigia: &mut Vigia) -> Result<Vec<String>, String> {
    let foto = win::retrato()?;
    Ok(vigia.comparar(foto, &win::existe))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN: &str = "C:\\Windows";
    const JOGO: &str = "D:\\RagnaLinK";

    fn achou(_: &str) -> Option<bool> {
        Some(true)
    }

    #[test]
    fn sistema_e_jogo_nao_sao_suspeitos() {
        for (c, esperado) in [
            ("C:\\Windows\\System32\\kernel32.dll", Origem::Sistema),
            ("C:\\WINDOWS\\SysWOW64\\ws2_32.dll", Origem::Sistema),
            ("D:\\RagnaLinK\\rse\\rse_watchdog.dll", Origem::Jogo),
            ("d:/ragnalink/data.dll", Origem::Jogo),
        ] {
            let o = classificar(c, WIN, JOGO, Some(true));
            assert_eq!(o, esperado, "{}", c);
            assert!(!o.suspeita(), "{} nao devia ser suspeito", c);
        }
    }

    #[test]
    fn pasta_volatil_vira_alta() {
        let o = classificar(
            "C:\\Users\\Fulano\\AppData\\Local\\Temp\\inj.dll",
            WIN,
            JOGO,
            Some(true),
        );
        assert_eq!(o, Origem::Volatil);
        assert_eq!(o.severidade(), "alta");
    }

    #[test]
    fn instalado_fora_do_jogo_vira_media() {
        // O caso do overlay: Discord, Steam, Afterburner. Suspeito, mas sem
        // urgência — é o falso-positivo que a primeira rodada existe para mapear.
        let o = classificar(
            "C:\\Program Files\\Discord\\overlay.dll",
            WIN,
            JOGO,
            Some(true),
        );
        assert_eq!(o, Origem::Instalado);
        assert_eq!(o.severidade(), "media");
    }

    #[test]
    fn arquivo_sumido_vira_fantasma() {
        let o = classificar("C:\\qualquer\\x.dll", WIN, JOGO, Some(false));
        assert_eq!(o, Origem::Fantasma);
        assert_eq!(o.severidade(), "alta");
    }

    #[test]
    fn caminho_vazio_vira_fantasma() {
        assert_eq!(classificar("", WIN, JOGO, None), Origem::Fantasma);
    }

    #[test]
    fn nao_sei_nao_vira_fantasma() {
        // 🚨 A regra do 6.1 aplicada aqui: acesso negado (`None`) NÃO pode virar
        // a severidade mais alta. Seria acusar em cima de erro de API.
        let o = classificar("C:\\Program Files\\AV\\hook.dll", WIN, JOGO, None);
        assert_eq!(o, Origem::Instalado);
    }

    #[test]
    fn jogo_dentro_de_downloads_nao_e_volatil() {
        // Alguém descompactou o cliente em Downloads. Sem a ordem certa das
        // checagens, TODA DLL do jogo viraria `volatil` e a detecção nasceria
        // inútil na primeira varredura.
        let jogo = "C:\\Users\\Fulano\\Downloads\\RagnaLinK";
        let o = classificar(
            "C:\\Users\\Fulano\\Downloads\\RagnaLinK\\rse\\rse_watchdog.dll",
            WIN,
            jogo,
            Some(true),
        );
        assert_eq!(o, Origem::Jogo);
    }

    #[test]
    fn redige_o_nome_de_usuario() {
        assert_eq!(
            redigir_usuario("C:\\Users\\Phillipe\\AppData\\Local\\Temp\\x.dll"),
            "C:\\Users\\*\\AppData\\Local\\Temp\\x.dll"
        );
        // Sem barra depois do nome: ainda assim não vaza.
        assert_eq!(redigir_usuario("C:\\Users\\Phillipe"), "C:\\Users\\*");
        // Nada a redigir: devolve igual.
        assert_eq!(
            redigir_usuario("C:\\Windows\\System32\\a.dll"),
            "C:\\Windows\\System32\\a.dll"
        );
    }

    #[test]
    fn nenhum_relato_menciona_o_usuario() {
        // Teste de rede: a garantia do §8 tem que valer na linha final, não só
        // na função de redação isolada.
        let suspeitos = vec![(
            Modulo {
                nome: "inj.dll".into(),
                caminho: "C:\\Users\\Phillipe\\Downloads\\inj.dll".into(),
            },
            Origem::Volatil,
        )];
        for l in linhas(&suspeitos, true, 80) {
            assert!(!l.to_lowercase().contains("phillipe"), "vazou: {}", l);
        }
    }

    #[test]
    fn relato_nao_usa_o_separador_de_campo() {
        // `detail` não pode conter `|` nem `\n` (mensagens.rs). Caminho do
        // Windows não tem `|`, mas o teste trava a regra caso o formato mude.
        let suspeitos = vec![(
            Modulo {
                nome: "a.dll".into(),
                caminho: "C:\\Program Files\\X\\a.dll".into(),
            },
            Origem::Instalado,
        )];
        for l in linhas(&suspeitos, true, 10) {
            assert_eq!(l.matches('|').count(), 2, "campos demais: {}", l);
            assert!(!l.contains('\n'));
        }
    }

    fn m(nome: &str, caminho: &str) -> Modulo {
        Modulo {
            nome: nome.into(),
            caminho: caminho.into(),
        }
    }

    #[test]
    fn linha_de_base_limpa_ainda_manda_inventario() {
        let foto = vec![
            m("ntdll.dll", "C:\\Windows\\System32\\ntdll.dll"),
            m("RagnaLinK.exe", "D:\\RagnaLinK\\RagnaLinK.exe"),
        ];
        let (_, linhas) = Vigia::a_partir_de(foto, WIN.into(), JOGO.into(), &achou);
        assert_eq!(linhas.len(), 1, "só o resumo");
        assert!(linhas[0].starts_with("6020|info|inventario no arranque: 2 modulo(s), 0 de fora"));
    }

    #[test]
    fn so_relata_o_que_e_novo_e_so_uma_vez() {
        let base = vec![m("ntdll.dll", "C:\\Windows\\System32\\ntdll.dll")];
        let (mut v, _) = Vigia::a_partir_de(base, WIN.into(), JOGO.into(), &achou);

        let com_injecao = vec![
            m("ntdll.dll", "C:\\Windows\\System32\\ntdll.dll"),
            m("inj.dll", "C:\\Users\\Fulano\\AppData\\Local\\Temp\\inj.dll"),
        ];
        let primeira = v.comparar(com_injecao.clone(), &achou);
        assert_eq!(primeira.len(), 1);
        assert!(primeira[0].starts_with("2000|alta|carregado depois do arranque: inj.dll"));

        // Segunda varredura com a MESMA situação: silêncio. É o que impede um
        // overlay de gerar a mesma linha a cada 30 s.
        assert!(v.comparar(com_injecao, &achou).is_empty());
    }

    #[test]
    fn modulo_de_sistema_carregado_depois_nao_vira_relato() {
        let (mut v, _) = Vigia::a_partir_de(vec![], WIN.into(), JOGO.into(), &achou);
        let depois = vec![m("d3d9.dll", "C:\\Windows\\SysWOW64\\d3d9.dll")];
        assert!(v.comparar(depois, &achou).is_empty());
    }

    #[test]
    fn teto_de_linhas_avisa_quantas_ficaram_de_fora() {
        let suspeitos: Vec<_> = (0..MAX_LINHAS + 5)
            .map(|i| {
                (
                    m(&format!("x{}.dll", i), &format!("C:\\Prog\\x{}.dll", i)),
                    Origem::Instalado,
                )
            })
            .collect();
        let l = linhas(&suspeitos, true, 100);
        assert_eq!(l.len(), MAX_LINHAS + 1);
        assert!(l.last().unwrap().contains("e mais 5 modulo(s)"));
    }
}
