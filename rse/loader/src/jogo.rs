//! Criacao do processo do jogo.
//!
//! # Por que suspenso
//!
//! `CREATE_SUSPENDED` cria o processo com a thread principal parada antes da
//! primeira instrucao do programa. E a unica forma de garantir que a DLL da
//! Fase 5 esteja carregada **antes** de o cliente rodar qualquer coisa. Retomar
//! primeiro e injetar depois deixaria uma janela - curta, mas suficiente - em
//! que o jogo roda sem protecao. E e exatamente essa janela que se procura.
//!
//! Nesta fase nao ha DLL, entao criamos suspenso e retomamos em seguida. Parece
//! trabalho a toa, e nao e: o encanamento fica pronto e testado, e a Fase 5
//! acrescenta so a injecao no meio, sem mexer no que ja funciona.
//!
//! # A armadilha do diretorio de trabalho
//!
//! `lpCurrentDirectory` e passado **explicitamente**. Sem isso o filho herda o
//! CWD do Loader, que, sendo um processo elevado criado pelo servico AppInfo,
//! nasce em `C:\Windows\System32`. O Ragexe abre `data.grf` e companhia por
//! caminho relativo: ele subiria e nao acharia nada, com uma mensagem de erro
//! que nao aponta para lugar nenhum.

use anyhow::Result;
use std::path::Path;

pub struct ProcessoFilho {
    pub pid: u32,
    #[cfg(windows)]
    handle_processo: winapi::um::winnt::HANDLE,
    #[cfg(windows)]
    handle_thread: winapi::um::winnt::HANDLE,
}

// SAFETY: handles do Windows sao valores opacos validos em todo o processo; nao
// ha ponteiro para memoria compartilhada aqui.
#[cfg(windows)]
unsafe impl Send for ProcessoFilho {}

/// Monta a linha de comando no formato que o `CommandLineToArgvW` desfaz.
///
/// # Por que isto nao e um `join(" ")`
///
/// O Windows nao passa vetor de argumentos: passa **uma string**, e cada
/// programa a reparte. A regra que o runtime C e o `CommandLineToArgvW` usam
/// tem dois detalhes que mordem:
///
/// - aspas dentro de um argumento precisam de barra invertida antes;
/// - barras invertidas so sao especiais **imediatamente antes de uma aspa** -
///   ai cada uma vira duas.
///
/// Caminho do Windows termina em barra invertida com frequencia
/// (`C:\Jogo\`), e citar isso ingenuamente produz `"C:\Jogo\"`, cuja ultima
/// aspa aparece escapada. O argumento seguinte e engolido junto. E o tipo de
/// bug que so aparece na maquina de um jogador.
///
/// O criterio de aceite "o `1sak1` chega intacto ao Ragexe" depende disto.
pub fn montar_linha_de_comando(exe: &str, args: &[String]) -> String {
    let mut linha = citar(exe);
    for a in args {
        linha.push(' ');
        linha.push_str(&citar(a));
    }
    linha
}

fn citar(arg: &str) -> String {
    // Sem espaco, tabulacao ou aspa, o argumento vai como esta. Vale a pena:
    // mantem a linha de comando legivel no Gerenciador de Tarefas, que e onde
    // alguem vai olhar quando algo der errado.
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut saida = String::with_capacity(arg.len() + 2);
    saida.push('"');
    let mut barras = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                barras += 1;
                saida.push('\\');
            }
            '"' => {
                // As barras acumuladas viram o dobro, e a aspa ganha a sua.
                for _ in 0..barras {
                    saida.push('\\');
                }
                barras = 0;
                saida.push('\\');
                saida.push('"');
            }
            outro => {
                barras = 0;
                saida.push(outro);
            }
        }
    }
    // Barras no fim precisam ser dobradas, senao escapam a aspa de fechamento.
    for _ in 0..barras {
        saida.push('\\');
    }
    saida.push('"');
    saida
}

#[cfg(windows)]
pub fn iniciar_suspenso(exe: &Path, dir: &Path, args: &[String]) -> Result<ProcessoFilho> {
    win::iniciar(exe, dir, args)
}

#[cfg(not(windows))]
pub fn iniciar_suspenso(_exe: &Path, _dir: &Path, _args: &[String]) -> Result<ProcessoFilho> {
    anyhow::bail!("o RSE Loader so roda no Windows")
}

/// Handle do processo, para a injeção da DLL (Fase 5).
///
/// Emprestado, não transferido: o `ProcessoFilho` continua dono e o fecha no
/// Drop. A `injecao` só usa durante a vida do `filho`.
#[cfg(windows)]
pub fn handle_do_processo(filho: &ProcessoFilho) -> winapi::um::winnt::HANDLE {
    filho.handle_processo
}

#[cfg(windows)]
pub fn retomar(filho: &ProcessoFilho) -> Result<()> {
    win::retomar(filho)
}

#[cfg(not(windows))]
pub fn retomar(_filho: &ProcessoFilho) -> Result<()> {
    anyhow::bail!("o RSE Loader so roda no Windows")
}

#[cfg(windows)]
mod win {
    use super::{montar_linha_de_comando, ProcessoFilho};
    use anyhow::{bail, Result};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{CreateProcessW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::winbase::CREATE_SUSPENDED;

    fn para_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    impl Drop for ProcessoFilho {
        fn drop(&mut self) {
            // SAFETY: os dois handles vieram de CreateProcessW e este tipo e o
            // unico dono deles.
            unsafe {
                if !self.handle_thread.is_null() {
                    CloseHandle(self.handle_thread);
                }
                if !self.handle_processo.is_null() {
                    CloseHandle(self.handle_processo);
                }
            }
        }
    }

    pub fn iniciar(exe: &Path, dir: &Path, args: &[String]) -> Result<ProcessoFilho> {
        let exe_txt = exe
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("caminho do jogo nao e UTF-8: {}", exe.display()))?;
        let dir_txt = dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("pasta do jogo nao e UTF-8: {}", dir.display()))?;

        let exe_w = para_wide(exe_txt);
        let dir_w = para_wide(dir_txt);
        // `lpCommandLine` e escrito pela API, entao precisa ser mutavel.
        let mut linha_w = para_wide(&montar_linha_de_comando(exe_txt, args));

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SAFETY: exe_w, linha_w e dir_w terminam em NUL e vivem ate o fim da
        // chamada; si e pi sao structs zeradas do tamanho correto.
        // bInheritHandles = FALSE: o Loader nao tem handle que o jogo deva
        // herdar, e herdar por descuido e como handle vaza para processo hostil.
        let ok = unsafe {
            CreateProcessW(
                exe_w.as_ptr(),
                linha_w.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                dir_w.as_ptr(),
                &mut si,
                &mut pi,
            )
        };

        if ok == 0 {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };

            // 740 = ERROR_ELEVATION_REQUIRED. Significa que o manifesto do
            // executavel do jogo pede `requireAdministrator` e o Loader NAO esta
            // elevado. Merece nome proprio: e exatamente o que acontece com quem
            // tem o cliente antigo depois de o launcher parar de elevar, e o
            // numero 740 sozinho nao diz nada a ninguem.
            const ERROR_ELEVATION_REQUIRED: u32 = 740;
            if erro == ERROR_ELEVATION_REQUIRED {
                bail!(
                    "CLIENTE_DESATUALIZADO: o executavel do jogo ainda exige \
                     administrador (erro 740). Atualize pelo launcher."
                );
            }

            bail!(
                "CreateProcessW falhou (erro {}) para {} na pasta {}",
                erro,
                exe.display(),
                dir.display()
            );
        }

        Ok(ProcessoFilho {
            pid: pi.dwProcessId,
            handle_processo: pi.hProcess,
            handle_thread: pi.hThread,
        })
    }

    pub fn retomar(filho: &ProcessoFilho) -> Result<()> {
        // SAFETY: o handle de thread veio de CreateProcessW e ainda esta aberto.
        let anterior = unsafe { ResumeThread(filho.handle_thread) };
        if anterior == u32::MAX {
            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            bail!("ResumeThread falhou (erro {})", erro);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn caso_real_do_ragnalink() {
        // O caso que de fato acontece: caminho com espaco, argumento simples.
        assert_eq!(
            montar_linha_de_comando(
                r"D:\DEV Ragnarok\ClienteRagnaLinK\RagnaLinK_ptBR5.exe",
                &s(&["1sak1"])
            ),
            r#""D:\DEV Ragnarok\ClienteRagnaLinK\RagnaLinK_ptBR5.exe" 1sak1"#
        );
    }

    #[test]
    fn argumento_simples_nao_ganha_aspas() {
        assert_eq!(montar_linha_de_comando("jogo.exe", &s(&["1sak1"])), "jogo.exe 1sak1");
    }

    #[test]
    fn argumento_com_espaco_ganha_aspas() {
        assert_eq!(
            montar_linha_de_comando("jogo.exe", &s(&["com espaco"])),
            r#"jogo.exe "com espaco""#
        );
    }

    /// Este e o que morde de verdade: caminho terminado em barra invertida.
    #[test]
    fn barra_no_fim_e_dobrada_para_nao_escapar_a_aspa() {
        let linha = montar_linha_de_comando("jogo.exe", &s(&[r"C:\Pasta Com Espaco\"]));
        assert_eq!(linha, r#"jogo.exe "C:\Pasta Com Espaco\\""#);
        // A aspa final tem que ficar viva: se as barras nao fossem dobradas,
        // ela seria escapada e o argumento seguinte entraria neste.
        assert!(linha.ends_with(r#"\\""#));
    }

    #[test]
    fn aspas_internas_sao_escapadas() {
        assert_eq!(
            montar_linha_de_comando("jogo.exe", &s(&[r#"diz "oi""#])),
            r#"jogo.exe "diz \"oi\"""#
        );
    }

    #[test]
    fn barras_antes_de_aspa_sao_dobradas() {
        assert_eq!(
            montar_linha_de_comando("jogo.exe", &s(&[r#"a\\"b"#])),
            r#"jogo.exe "a\\\\\"b""#
        );
    }

    #[test]
    fn barras_no_meio_nao_sao_dobradas() {
        // So barra ANTES de aspa (ou no fim, que vira antes da aspa de
        // fechamento) e especial. No meio, vai como esta.
        assert_eq!(
            montar_linha_de_comando("jogo.exe", &s(&[r"C:\um dois\tres"])),
            r#"jogo.exe "C:\um dois\tres""#
        );
    }

    #[test]
    fn argumento_vazio_vira_par_de_aspas() {
        assert_eq!(montar_linha_de_comando("jogo.exe", &s(&[""])), r#"jogo.exe """#);
    }

    #[test]
    fn sem_argumentos_sobra_so_o_executavel() {
        assert_eq!(montar_linha_de_comando("jogo.exe", &[]), "jogo.exe");
    }

    #[test]
    fn ordem_dos_argumentos_e_preservada() {
        assert_eq!(
            montar_linha_de_comando("jogo.exe", &s(&["1sak1", "-t:x", "server"])),
            "jogo.exe 1sak1 -t:x server"
        );
    }
}
