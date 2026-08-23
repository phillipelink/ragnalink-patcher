//! O que o Loader faz quando o servidor manda agir.
//!
//! # O buraco que este arquivo fecha
//!
//! Ao fim da Fase 6 havia cinco detecções funcionando e provadas em campo — e
//! **nenhuma delas fazia nada**. O `/report` do Auth Service devolvia
//! `action = "report"` escrito no código, o Loader repassava para a DLL, e a DLL
//! registrava no log. Fim.
//!
//! Ou seja: cinco dias de trabalho enchendo um arquivo que ninguém lê.
//!
//! Pior, o caminho de agir **existia no protocolo desde a Fase 2** (o
//! `REPORT_ACK` sempre carregou a ação) e nunca tinha sido exercitado uma vez.
//! Código que nunca rodou não é código que funciona — é código que ainda não
//! falhou na frente de ninguém.
//!
//! # 🚨 Isto NÃO liga o `kill` para ninguém
//!
//! O padrão continua `report` em todas as detecções, e a regra do RSE_SPEC §9
//! segue valendo: *severidade não é ação*. O que muda aqui é que a **máquina de
//! agir passa a existir e a ser testada**. Promover uma detecção para `kill`
//! vira uma variável de ambiente no servidor — sem recompilar DLL, sem
//! redistribuir cliente, sem tocar em jogador nenhum enquanto a telemetria não
//! justificar.
//!
//! Construir o mecanismo antes de precisar dele é de propósito: no dia em que um
//! cheat estiver em campo, mexer numa configuração é uma coisa; descobrir que o
//! caminho nunca funcionou é outra bem pior.
//!
//! # As três ações
//!
//! | Ação | O que acontece |
//! |---|---|
//! | `report` | só registra no servidor; o jogador não vê nada |
//! | `avisar` | encerra o cliente e explica, em tom de "conserte isto" |
//! | `matar` | encerra o cliente e explica, em tom de violação |
//!
//! # Por que `avisar` também encerra
//!
//! A primeira versão deixava o jogo rodando no `avisar`, com o argumento de que
//! entre "não faço nada" e "derrubo o jogador" cabe um degrau: a detecção está
//! certa, a pessoa não é trapaceira, e só precisa saber para consertar.
//!
//! O teste em campo desmontou isso. Um aviso que não interrompe **não é lido**:
//! a caixa nasce atrás da janela do jogo, e quem está jogando não para para
//! procurá-la na barra de tarefas. Pior, quem *quer* ignorar simplesmente
//! ignora. O degrau existia no papel e não existia na tela.
//!
//! Então o que separa os dois hoje é o **texto e o registro**, não o desfecho:
//! `avisar` fala em consertar (arquivo desatualizado, overlay atrapalhando),
//! `matar` fala em violação. Os dois encerram.
//!
//! É menos gradação do que o desenho original previa, e vale dizer em voz alta:
//! **a distinção só volta a ter peso quando houver consequência do lado do
//! servidor** — revogar a sessão, marcar a conta. Aí `avisar` vira "feche e
//! volte" e `matar` vira "feche e converse com o suporte". Enquanto isso não
//! existir, tratar os dois como fechamento é mais honesto do que fingir uma
//! escada de três degraus que a tela não sustenta.
//!
//! # E a regra que já custou caro hoje
//!
//! **Nunca matar em silêncio.** Um cliente que fecha sozinho, sem explicação,
//! vira chamado de suporte dizendo "o jogo não abre" — e a pessoa acha que o
//! problema é do servidor. Já aconteceu neste projeto com as falhas do Loader, e
//! a lição virou o `auth::explicar()`. Aqui vale igual: toda ação que interrompe
//! o jogador mostra o motivo.
//!
//! # 🚨 Duas coisas que o primeiro teste em campo derrubou
//!
//! A versão inicial mostrava a caixa **antes** de encerrar, com o argumento de
//! que o jogador precisava ler o motivo enquanto o jogo ainda estava de pé. O
//! argumento era errado nos dois sentidos, e o teste mostrou por quê:
//!
//! **1. A caixa abria atrás do jogo.** `MessageBox` do Loader não consegue roubar
//! o primeiro plano do cliente — o Windows só permite que o processo que já está
//! na frente ceda a vez. Nem `MB_TOPMOST` nem `MB_SETFOREGROUND` vencem isso.
//! Resultado: o jogador só via a caixa piscando na barra de tarefas.
//!
//! **2. Quem não clicasse continuava jogando.** `MessageBox` é bloqueante. O
//! `matar` só acontecia *depois* do clique — então bastava não clicar. Um
//! trapaceiro pego pela detecção mais grave do sistema simplesmente ignorava a
//! janela e seguia a partida. É a diferença entre uma ação e uma sugestão.
//!
//! Pior: enquanto a caixa esperava o clique, o laço do heartbeat do Loader
//! ficava parado. Três batimentos sem resposta e a **DLL** derruba o cliente por
//! conta própria — ou seja, o jogo até morreria, mas por "perdi o Loader",
//! quinze segundos depois e com a mensagem errada no log.
//!
//! A ordem correta é a inversa, e ela resolve os três problemas de uma vez:
//! **encerra o jogo primeiro, explica depois.** Sem janela do cliente por cima,
//! a caixa fica visível; sem espera pelo clique, a ação é imediata; e a caixa
//! pertence ao *Loader*, que continua vivo — matar o jogo não a fecha.
//!
//! Vale para as duas ações que interrompem, pelo mesmo motivo.

/// O que o servidor decidiu para um lote de violações.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Acao {
    /// Só registra. É o padrão de toda detecção nova.
    Reportar,
    /// Mostra o motivo ao jogador; o jogo continua.
    Avisar,
    /// Mostra o motivo e encerra o cliente.
    Matar,
}

impl Acao {
    /// Interpreta o que o Auth Service respondeu.
    ///
    /// **Qualquer coisa que não reconheçamos vira `Reportar`.** É a direção
    /// segura de errar: um servidor mais novo que este Loader pode inventar uma
    /// ação nova, e a resposta certa para "não entendi" nunca é derrubar o
    /// jogador. O contrário — tratar desconhecido como `matar` — transformaria
    /// um deploy de servidor em queda em massa de clientes antigos.
    pub fn ler(texto: &str) -> Acao {
        match texto.trim().to_ascii_lowercase().as_str() {
            "kill" | "matar" => Acao::Matar,
            "warn" | "avisar" => Acao::Avisar,
            _ => Acao::Reportar,
        }
    }

    /// Como sai no log e no `REPORT_ACK` para a DLL.
    pub fn como_texto(self) -> &'static str {
        match self {
            Acao::Reportar => "report",
            Acao::Avisar => "warn",
            Acao::Matar => "kill",
        }
    }

    /// Esta ação interrompe o jogador?
    pub fn incomoda(self) -> bool {
        !matches!(self, Acao::Reportar)
    }
}

/// Traduz as violações para uma frase que o jogador consiga usar.
///
/// Recebe os códigos porque a mesma ação (`matar`) significa coisas muito
/// diferentes conforme o motivo: arquivos alterados se resolve deixando o
/// launcher atualizar; depurador anexado se resolve fechando o programa.
///
/// O caso desconhecido **não inventa diagnóstico** — mostra o código e pede o
/// log, que é a mesma regra do `auth::explicar()`.
pub fn explicar_violacoes(codigos: &[u32]) -> String {
    let tem = |c: u32| codigos.contains(&c);

    let motivo = if tem(1000) || tem(1001) || tem(1002) {
        "Os arquivos do seu cliente estão diferentes dos do servidor.\n\n\
         Feche o jogo e abra pelo launcher, deixando ele atualizar até o fim."
    } else if tem(3001) {
        "Foi detectado um depurador anexado ao jogo.\n\n\
         Feche programas de depuração e engenharia reversa e abra o jogo de novo."
    } else if tem(3000) {
        "Foi detectado um programa não permitido em execução.\n\n\
         Feche editores de memória e editores de pacote antes de jogar."
    } else if tem(3002) || tem(2003) {
        "A memória do jogo foi alterada por outro programa.\n\n\
         Feche programas que modificam jogos e abra o cliente de novo."
    } else if tem(3004) {
        "O relógio do jogo está sendo alterado por outro programa.\n\n\
         Feche programas de aceleração de velocidade e abra o jogo de novo."
    } else if tem(3003) {
        "Outro programa está com acesso de escrita à memória do jogo.\n\n\
         Feche editores de memória antes de jogar."
    } else if tem(2000) {
        "Foi carregado no jogo um componente que o RagnaShield não reconhece.\n\n\
         Se você usa overlay (Discord, Steam, gravador de tela), tente fechá-lo."
    } else {
        return format!(
            "A proteção do RagnaLinK interrompeu esta sessão.\n\n\
             Código(s): {}\n\n\
             Se você não usa nenhum programa de trapaça, mande o arquivo \
             rse_loader.log ao suporte.",
            lista(codigos)
        );
    };

    format!("{}\n\nCódigo(s): {}", motivo, lista(codigos))
}

fn lista(codigos: &[u32]) -> String {
    if codigos.is_empty() {
        return "—".to_string();
    }
    let mut v: Vec<String> = codigos.iter().map(|c| c.to_string()).collect();
    v.sort();
    v.dedup();
    v.join(", ")
}

/// Executa a ação decidida pelo servidor.
///
/// Devolve `true` se a sessão deve terminar. Quem encerra o processo do jogo é
/// o chamador, que é quem tem o handle — esta função só decide e explica.
/// O jogo deve ser encerrado por causa desta ação?
///
/// **Não mostra caixa nenhuma** — quem explica é o `explicar_apos_encerrar`,
/// chamado depois de o cliente já ter morrido. Ver o cabeçalho para o porquê.
pub fn aplicar(acao: Acao, _codigos: &[u32]) -> bool {
    acao.incomoda()
}

/// Explica ao jogador **depois** de o cliente ter sido encerrado.
///
/// Bloqueia até o clique, e isso agora é desejável: o jogo já acabou, não há
/// heartbeat para manter, e a caixa é a última coisa que o Loader faz. Sem a
/// janela do cliente por cima, ela finalmente aparece na frente.
///
/// O ícone segue a ação: triângulo para "conserte isto", X para violação. É o
/// que sobrou de diferença entre as duas, e é pouco — ver o cabeçalho.
#[cfg(windows)]
pub fn explicar_apos_encerrar(acao: Acao, codigos: &[u32]) {
    let icone = match acao {
        Acao::Matar => crate::MB_ICONERROR,
        _ => crate::MB_ICONWARNING,
    };
    crate::caixa(&explicar_violacoes(codigos), icone);
}

#[cfg(not(windows))]
pub fn explicar_apos_encerrar(_acao: Acao, _codigos: &[u32]) {}

// ===========================================================================
//  Testes
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_as_tres_acoes_nos_dois_idiomas() {
        assert_eq!(Acao::ler("kill"), Acao::Matar);
        assert_eq!(Acao::ler("matar"), Acao::Matar);
        assert_eq!(Acao::ler("warn"), Acao::Avisar);
        assert_eq!(Acao::ler("avisar"), Acao::Avisar);
        assert_eq!(Acao::ler("report"), Acao::Reportar);
    }

    #[test]
    fn tolera_espaco_e_caixa() {
        assert_eq!(Acao::ler("  KILL  "), Acao::Matar);
        assert_eq!(Acao::ler("Warn\n"), Acao::Avisar);
    }

    /// 🚨 A direção segura de errar.
    ///
    /// Um servidor mais novo que este Loader pode responder uma ação que ele
    /// não conhece. Tratar desconhecido como `matar` faria um deploy de servidor
    /// derrubar todos os clientes antigos de uma vez.
    #[test]
    fn acao_desconhecida_nunca_mata() {
        for t in ["", "banir", "quarentena", "KILL_ALL", "42", "réport"] {
            assert_eq!(Acao::ler(t), Acao::Reportar, "entrada: {:?}", t);
        }
    }

    #[test]
    fn so_reportar_nao_incomoda_o_jogador() {
        assert!(!Acao::Reportar.incomoda());
        assert!(Acao::Avisar.incomoda());
        assert!(Acao::Matar.incomoda());
    }

    /// Trava a decisão de 23/08: avisar TAMBÉM encerra.
    ///
    /// A versão anterior deixava o jogo rodando no `avisar`, e o teste em campo
    /// mostrou que um aviso que não interrompe não é lido — a caixa nasce atrás
    /// da janela do jogo.
    #[test]
    fn avisar_e_matar_encerram_o_jogo() {
        assert!(aplicar(Acao::Avisar, &[1000]));
        assert!(aplicar(Acao::Matar, &[1000]));
    }

    #[test]
    fn reportar_nunca_encerra() {
        assert!(!aplicar(Acao::Reportar, &[1000, 3001, 3004]));
    }

    #[test]
    fn ida_e_volta_do_texto() {
        for a in [Acao::Reportar, Acao::Avisar, Acao::Matar] {
            assert_eq!(Acao::ler(a.como_texto()), a);
        }
    }

    #[test]
    fn cada_familia_de_codigo_tem_frase_propria() {
        let integridade = explicar_violacoes(&[1000]);
        let depurador = explicar_violacoes(&[3001]);
        let memoria = explicar_violacoes(&[3002]);
        assert!(integridade.contains("arquivos"), "{}", integridade);
        assert!(depurador.contains("depurador"), "{}", depurador);
        assert!(memoria.contains("memória"), "{}", memoria);
        assert_ne!(integridade, depurador);
        assert_ne!(depurador, memoria);
    }

    /// O código desconhecido não pode inventar diagnóstico — mesma regra do
    /// `auth::explicar()`. Mostra o número e pede o log.
    #[test]
    fn codigo_desconhecido_pede_o_log_em_vez_de_chutar() {
        let t = explicar_violacoes(&[9999]);
        assert!(t.contains("9999"), "{}", t);
        assert!(t.contains("rse_loader.log"), "{}", t);
    }

    #[test]
    fn a_mensagem_sempre_mostra_os_codigos() {
        for c in [1000u32, 3001, 3002, 3004, 2000, 7777] {
            let t = explicar_violacoes(&[c]);
            assert!(t.contains(&c.to_string()), "codigo {} sumiu de: {}", c, t);
        }
    }

    #[test]
    fn codigos_repetidos_aparecem_uma_vez_so() {
        let t = explicar_violacoes(&[3001, 3001, 3001]);
        assert_eq!(t.matches("3001").count(), 1, "{}", t);
    }
}
