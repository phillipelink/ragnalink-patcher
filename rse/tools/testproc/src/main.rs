//! `rse-testproc` — finge ser um processo proibido, para exercitar a detecção
//! `3000 FORBIDDEN_PROCESS` da Fase 6.4.
//!
//! ```text
//! cargo run -p rse-testproc              # finge por 90 s
//! cargo run -p rse-testproc -- 45        # por 45 s
//! ```
//!
//! # Por que esta ferramenta existe
//!
//! Testar a detecção exigiria **baixar e instalar o Cheat Engine de verdade**.
//! Não precisa — e não deve. Baixar cheat de fórum para testar anti-cheat é
//! como testar antivírus baixando vírus: funciona, e um dia dá errado.
//!
//! Não precisa porque a detecção da Fase 6.4 olha **exclusivamente o nome do
//! executável**. Ela não lê a memória do processo, não confere assinatura, não
//! olha o que ele faz. Então qualquer programa chamado `cheatengine-x86_64.exe`
//! aciona a detecção **exatamente** igual ao Cheat Engine real.
//!
//! Esta ferramenta se copia para o `%TEMP%` com um nome da lista de proibidos,
//! roda a cópia, espera, e limpa.
//!
//! # 🚨 O que este teste também prova, sem querer
//!
//! Se um programa inocente com o nome certo dispara a detecção, então o
//! contrário também vale: **o Cheat Engine renomeado não dispara nada**.
//!
//! Isso não é defeito de implementação, é o teto da técnica — toda blocklist
//! por nome tem esse teto. Está documentado no cabeçalho do `processos.rs` e
//! vale repetir aqui, onde é impossível não ver: a 6.4 pega o sujeito casual,
//! que é a maioria de quem tenta. Não pega quem se preparou. Quem se preparou é
//! trabalho da 6.2 (módulos carregados) e da 6.5 (hooks), que olham o que o
//! programa **faz**, não como ele se chama.

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
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    /// Nome escolhido da lista de `processos.rs`. O Cheat Engine é o caso mais
    /// representativo: é o que aparece em 90% dos tutoriais de cheat de RO.
    const NOME_FALSO: &str = "cheatengine-x86_64.exe";

    /// Marca de argumento que diz "você é a cópia, só durma".
    ///
    /// Sem isto a cópia se copiaria de novo, em recursão infinita — cada
    /// geração criando a próxima. Aprendi isso da forma cara uma vez.
    const MARCA_FILHO: &str = "--sou-a-copia";

    pub fn executar() {
        let args: Vec<String> = std::env::args().collect();

        // --- modo cópia: só existir e dormir --------------------------------
        if args.iter().any(|a| a == MARCA_FILHO) {
            let segundos: u64 = args
                .iter()
                .skip_while(|a| *a != MARCA_FILHO)
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(90);
            std::thread::sleep(Duration::from_secs(segundos));
            return;
        }

        // --- modo principal --------------------------------------------------
        let segundos: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(90);

        let eu = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("nao consegui achar o meu proprio caminho: {}", e);
                std::process::exit(1);
            }
        };

        let destino: PathBuf = std::env::temp_dir().join(NOME_FALSO);

        if let Err(e) = std::fs::copy(&eu, &destino) {
            eprintln!(
                "nao consegui copiar para {}: {}\n\
                 Se o antivirus bloqueou, e esperado: um executavel se copiando \
                 com nome de cheat e exatamente o padrao que ele procura. \
                 Libere a pasta ou rode o teste manual do LEIA-ME.",
                destino.display(),
                e
            );
            std::process::exit(1);
        }

        println!("copiei para: {}", destino.display());
        println!("subindo o processo falso por {} s...", segundos);

        let filho = Command::new(&destino)
            .arg(MARCA_FILHO)
            .arg(segundos.to_string())
            .spawn();

        let mut filho = match filho {
            Ok(f) => f,
            Err(e) => {
                eprintln!("nao consegui subir a copia: {}", e);
                let _ = std::fs::remove_file(&destino);
                std::process::exit(1);
            }
        };

        println!();
        println!("  Processo '{}' esta no ar (pid {}).", NOME_FALSO, filho.id());
        println!("  O RagnaShield varre a cada 30 s — aguarde ate meio minuto.");
        println!("  Esperado no log do servidor:");
        println!("    RSE: violacao 3000 sev=alta detalhe=processo proibido em execucao: {}", NOME_FALSO);
        println!();

        let _ = filho.wait();

        // Limpeza. Se falhar, avisa em vez de deixar lixo com nome de cheat
        // esquecido no %TEMP% do jogador — que seria uma pegadinha cruel.
        match std::fs::remove_file(&destino) {
            Ok(()) => println!("processo encerrado e copia removida."),
            Err(e) => println!(
                "processo encerrado, mas nao consegui remover {}: {}\n\
                 Apague na mao.",
                destino.display(),
                e
            ),
        }
        println!("Em ate 30 s o log deve mostrar: 'processos: {} encerrado'", NOME_FALSO);
    }
}
