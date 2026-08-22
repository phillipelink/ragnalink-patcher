//! Lado cliente do pipe de handover: recebe a credencial de sessao do launcher.
//!
//! # O contrato
//!
//! O **launcher** cria o pipe e escreve; o **Loader** conecta e le. Nessa ordem,
//! e por um motivo: se o Loader criasse o pipe, haveria uma janela entre o
//! launcher decidir o nome e o Loader realmente criar o objeto - e qualquer
//! processo do mesmo usuario poderia criar um pipe com aquele nome antes e
//! receber a credencial. Com o launcher criando **antes** de disparar o Loader,
//! o nome so existe depois que o objeto existe, e o objeto ja nasce com a DACL
//! certa.
//!
//! # Sobre os prazos
//!
//! O prazo vale para **conectar**, nao para ler. Isso e proposital:
//!
//! - Conectar pode demorar bastante, porque o launcher so escreve depois que o
//!   jogador aceitou o UAC - e ele pode ficar olhando o dialogo por um minuto.
//! - Depois de conectado, ou o launcher escreve em milissegundos, ou ele
//!   morreu - e nesse caso o `ReadFile` volta com ERROR_BROKEN_PIPE na hora.
//!
//! Ou seja, o caso "travar para sempre esperando bytes" nao existe: o proprio
//! sistema operacional avisa. Isso evita I/O sobreposto (`OVERLAPPED`) aqui, que
//! seria bem mais codigo para nao cobrir nenhum caso a mais.

use anyhow::{anyhow, Result};
use rse_protocol::handover;

/// Monta o caminho completo do pipe a partir do nome curto.
///
/// Aceita tanto `rse-abc123` quanto o caminho ja completo, para o mesmo valor
/// poder ser digitado a mao num diagnostico sem virar pegadinha.
pub fn caminho_do_pipe(nome: &str) -> String {
    if nome.starts_with(r"\\.\pipe\") {
        nome.to_string()
    } else {
        format!(r"\\.\pipe\{}", nome)
    }
}

#[cfg(windows)]
pub fn receber_credencial(nome: &str, timeout_ms: u32) -> Result<String> {
    win::receber(&caminho_do_pipe(nome), timeout_ms)
}

#[cfg(not(windows))]
pub fn receber_credencial(_nome: &str, _timeout_ms: u32) -> Result<String> {
    anyhow::bail!("o RSE Loader so roda no Windows")
}

/// Interpreta os bytes lidos. Fora do modulo `win` de proposito: assim esta
/// parte, que e onde erro de formato apareceria, tem teste em qualquer sistema.
fn montar_credencial(cabecalho: &[u8], corpo: &[u8]) -> Result<String> {
    let mut tudo = Vec::with_capacity(cabecalho.len() + corpo.len());
    tudo.extend_from_slice(cabecalho);
    tudo.extend_from_slice(corpo);
    handover::parse(&tudo).map_err(|e| anyhow!("quadro de handover invalido: {}", e))
}

#[cfg(windows)]
mod win {
    use super::montar_credencial;
    use anyhow::{anyhow, bail, Result};
    use rse_protocol::handover::HANDOVER_HEADER_LEN;
    use rse_protocol::handover;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use winapi::shared::winerror::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::fileapi::{CreateFileW, ReadFile, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::namedpipeapi::WaitNamedPipeW;
    use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, HANDLE};

    fn para_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Fecha o handle em qualquer saida, inclusive por `?` no meio da funcao.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                // SAFETY: o handle veio de CreateFileW e ainda nao foi fechado -
                // este tipo e o unico dono dele.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// Tenta abrir o pipe ate o prazo acabar.
    ///
    /// Dois motivos de falha sao **temporarios** e merecem nova tentativa:
    /// o pipe ainda nao existe (o launcher pode nao ter criado) e o pipe existe
    /// mas todas as instancias estao ocupadas.
    fn conectar(caminho_w: &[u16], caminho: &str, timeout_ms: u32) -> Result<Handle> {
        let inicio = std::time::Instant::now();
        let prazo = std::time::Duration::from_millis(timeout_ms as u64);

        loop {
            // SAFETY: caminho_w termina em NUL; os demais parametros sao
            // constantes da API ou ponteiros nulos permitidos pela assinatura.
            let h = unsafe {
                CreateFileW(
                    caminho_w.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };

            if h != INVALID_HANDLE_VALUE {
                return Ok(Handle(h));
            }

            // SAFETY: leitura do ultimo erro da thread corrente.
            let erro = unsafe { GetLastError() };
            let temporario = erro == ERROR_PIPE_BUSY || erro == ERROR_FILE_NOT_FOUND;
            if !temporario {
                bail!("CreateFileW em {} falhou com erro {}", caminho, erro);
            }

            let gasto = inicio.elapsed();
            if gasto >= prazo {
                bail!(
                    "o launcher nao disponibilizou o pipe {} em {} ms (ultimo erro {})",
                    caminho,
                    timeout_ms,
                    erro
                );
            }

            // Espera o pipe ficar disponivel, sem consumir CPU. O teto de 250 ms
            // por rodada mantem a checagem do prazo responsiva.
            let restante = (prazo - gasto).as_millis().min(250) as u32;
            // SAFETY: mesma string com NUL; a API aceita qualquer prazo em ms.
            unsafe { WaitNamedPipeW(caminho_w.as_ptr(), restante.max(1)) };
        }
    }

    /// Le exatamente `buf.len()` bytes, ou explica por que nao deu.
    ///
    /// `ReadFile` num pipe pode voltar com menos bytes do que se pediu; tratar
    /// isso como leitura completa e um classico, e daria um erro de formato
    /// confuso la na frente em vez do erro real aqui.
    fn ler_exato(h: &Handle, buf: &mut [u8], oque: &str) -> Result<()> {
        let mut lidos_total = 0usize;
        while lidos_total < buf.len() {
            let mut lidos: u32 = 0;
            let fatia = &mut buf[lidos_total..];
            // SAFETY: `h` e valido; `fatia` aponta para memoria valida de
            // `fatia.len()` bytes; `lidos` recebe a contagem.
            let ok = unsafe {
                ReadFile(
                    h.0,
                    fatia.as_mut_ptr() as *mut _,
                    fatia.len() as u32,
                    &mut lidos,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: leitura do ultimo erro da thread corrente.
                let erro = unsafe { GetLastError() };
                bail!("ReadFile falhou lendo {} (erro {})", oque, erro);
            }
            if lidos == 0 {
                bail!(
                    "o launcher fechou o pipe no meio de {} ({} de {} bytes)",
                    oque,
                    lidos_total,
                    buf.len()
                );
            }
            lidos_total += lidos as usize;
        }
        Ok(())
    }

    pub fn receber(caminho: &str, timeout_ms: u32) -> Result<String> {
        let caminho_w = para_wide(caminho);
        let h = conectar(&caminho_w, caminho, timeout_ms)?;

        // Cabecalho primeiro: e ele que diz quanto falta. Ler assim evita
        // alocar um buffer grande com base em numero que ainda nao conferimos.
        let mut cabecalho = [0u8; HANDOVER_HEADER_LEN];
        ler_exato(&h, &mut cabecalho, "o cabecalho do handover")?;

        let tamanho = handover::parse_header(&cabecalho)
            .map_err(|e| anyhow!("cabecalho de handover invalido: {}", e))?;

        let mut corpo = vec![0u8; tamanho];
        ler_exato(&h, &mut corpo, "a credencial")?;

        montar_credencial(&cabecalho, &corpo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rse_protocol::handover::HANDOVER_HEADER_LEN;

    #[test]
    fn caminho_aceita_nome_curto_e_completo() {
        assert_eq!(caminho_do_pipe("rse-abc"), r"\\.\pipe\rse-abc");
        assert_eq!(caminho_do_pipe(r"\\.\pipe\rse-abc"), r"\\.\pipe\rse-abc");
    }

    #[test]
    fn montar_credencial_junta_cabecalho_e_corpo() {
        let cred = "v1.teste.credencial";
        let quadro = handover::serialize(cred).unwrap();
        let (cab, corpo) = quadro.split_at(HANDOVER_HEADER_LEN);
        assert_eq!(montar_credencial(cab, corpo).unwrap(), cred);
    }

    #[test]
    fn montar_credencial_reprova_corpo_curto() {
        let quadro = handover::serialize("v1.teste.credencial").unwrap();
        let (cab, corpo) = quadro.split_at(HANDOVER_HEADER_LEN);
        assert!(montar_credencial(cab, &corpo[..corpo.len() - 1]).is_err());
    }
}
