//! Integridade dos arquivos críticos — Fase 5c.
//!
//! # O que esta etapa (5c-2b) confere
//!
//! Contra o `rse_manifest.txt` (gerado pelo `rse-manifest`, ao lado do jogo):
//!
//! | modo | arquivo | o que é lido | violação se não bater |
//! |---|---|---|---|
//! | `full` | o `.exe` | tudo (12 MB) | `1000 INTEGRITY_EXE_MISMATCH` |
//! | `header_only` | as `.grf` | cabeçalho + tabela de arquivos | `1001 INTEGRITY_GRF_MISMATCH` |
//!
//! Ler os 3,8 GB do `data.grf` a cada JOGAR somaria dezenas de segundos e o
//! jogador acharia que travou. O `header_only` resolve porque **toda** ferramenta
//! de edição de GRF reconstrói a tabela de arquivos ao salvar: trocar,
//! acrescentar ou remover qualquer arquivo muda offset, tamanho ou nome — e
//! portanto muda o hash da tabela.
//!
//! # Ainda é modo report — e as duas limitações, ditas com todas as letras
//!
//! A DLL **só relata**; a ação vem do `REPORT_ACK`, e o servidor está em report
//! (§9 do RSE_SPEC: *severidade não é ação*). E há dois furos conhecidos:
//!
//! 1. **`header_only` não pega** quem sobrescreve o conteúdo de um arquivo *no
//!    lugar*, mantendo tamanho comprimido e offset idênticos. Fecha com o modo
//!    `sampled` (blocos amostrados pelo `session_id`), previsto e não feito.
//! 2. **O manifesto é um arquivo local.** Quem adultera a GRF pode rodar o
//!    `rse-manifest` e gerar um manifesto que combine. Fecha amarrando o
//!    `client_hash` do ticket ao SHA-256 do manifesto — com o **servidor**
//!    decidindo o hash esperado pelo `patch_index`, em vez de ecoar o que o
//!    cliente mandou.
//!
//! Ou seja: hoje isto é **detecção honesta de adulteração casual**, não barreira
//! contra adversário dedicado. O modo report do servidor está coerente com isso.

#![cfg(windows)]

use rse_protocol::crypto::{sha256, to_hex};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

// Códigos do RSE_SPEC §9 (faixa 6000+ é a experimental, para telemetria).
const COD_EXE_MISMATCH: u16 = 1000; // INTEGRITY_EXE_MISMATCH — crítica
const COD_GRF_MISMATCH: u16 = 1001; // INTEGRITY_GRF_MISMATCH — crítica
const COD_MANIFESTO_SEM_EXE: u16 = 1002; // INTEGRITY_MANIFEST_MISSING — alta
const COD_OBSERVADA: u16 = 6001; // telemetria: sem manifesto, só o SHA visto
const COD_EXE_OK: u16 = 6002; // telemetria: exe conferido e bateu
const COD_GRF_OK: u16 = 6003; // telemetria: resumo das GRFs conferidas

/// Nome do manifesto, procurado ao lado do executável do jogo.
const NOME_MANIFESTO: &str = "rse_manifest.txt";

/// Cabeçalho GRF — os mesmos números que o `gruf/` do launcher usa.
const GRF_MAGIC: &[u8; 16] = b"Master of Magic\0";
const GRF_HEADER_SIZE: usize = 46;
const OFF_TABLE_OFFSET: usize = 30;

/// Uma entrada do manifesto.
struct Entrada {
    nome: String,
    modo: String,
    sha: String,
}

/// Confere tudo e devolve as linhas de violação para o `REPORT`
/// (`code|severity|detail`, uma por linha). Lista vazia = nem o `.exe` deu para
/// ler, e aí não há o que reportar.
pub fn verificar() -> Vec<String> {
    let caminho_exe = match crate::sys::caminho_do_exe() {
        Some(c) => c,
        None => return Vec::new(),
    };
    let dir = match Path::new(&caminho_exe).parent() {
        Some(d) => d.to_path_buf(),
        None => return Vec::new(),
    };
    let nome_exe = Path::new(&caminho_exe)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let manifesto = dir.join(NOME_MANIFESTO);
    let entradas = ler_manifesto(&manifesto);

    let mut saida = Vec::new();

    // ---- o .exe, modo full ------------------------------------------------
    let sha_exe = match std::fs::read(&caminho_exe) {
        Ok(b) => Some((to_hex(&sha256(&b)), b.len() as u64)),
        Err(_) => None,
    };

    match (&sha_exe, entradas.as_ref()) {
        (Some((sha, tam)), None) => {
            // Sem manifesto: telemetria pura (alimenta a linha de base do servidor).
            saida.push(format!("{}|info|exe sha={} size={}", COD_OBSERVADA, sha, tam));
            return saida;
        }
        (Some((sha, _)), Some(es)) => {
            match es
                .iter()
                .find(|e| e.modo == "full" && e.nome.to_lowercase() == nome_exe)
            {
                Some(e) if sha.eq_ignore_ascii_case(&e.sha) => {
                    saida.push(format!("{}|info|exe ok sha={}", COD_EXE_OK, sha))
                }
                Some(e) => saida.push(format!(
                    "{}|critica|exe MISMATCH sha={} esperado={}",
                    COD_EXE_MISMATCH, sha, e.sha
                )),
                None => saida.push(format!(
                    "{}|alta|manifesto presente mas sem a entrada do exe",
                    COD_MANIFESTO_SEM_EXE
                )),
            }
        }
        (None, _) => { /* nem o exe leu; segue para as GRFs assim mesmo */ }
    }

    // ---- as GRFs, modo header_only ----------------------------------------
    if let Some(es) = entradas {
        let mut ok = 0usize;
        let mut ilegiveis: Vec<String> = Vec::new();
        for e in es.iter().filter(|e| e.modo == "header_only") {
            let alvo = dir.join(&e.nome);
            match hash_header_grf(&alvo) {
                Ok(sha) if sha.eq_ignore_ascii_case(&e.sha) => ok += 1,
                Ok(sha) => saida.push(format!(
                    "{}|critica|grf MISMATCH {} sha={} esperado={}",
                    COD_GRF_MISMATCH, e.nome, sha, e.sha
                )),
                // Arquivo ausente ou ilegível NÃO vira violação crítica: uma GRF
                // opcional que o jogador não baixou, ou um arquivo que o jogo
                // abriu em modo exclusivo, não é adulteração. Mas o NOME e o
                // motivo vão no relato: "ilegivel" sem dizer qual é a diferença
                // entre diagnóstico e ruído — e se a `data.grf` cair sempre nesta
                // vala, a verificação está cega justamente onde mais importa.
                Err(motivo) => {
                    crate::sys::log_dll(&format!("integridade: {} ilegivel — {}", e.nome, motivo));
                    ilegiveis.push(e.nome.clone());
                }
            }
        }
        if ok > 0 || !ilegiveis.is_empty() {
            saida.push(format!(
                "{}|info|grf ok={} ilegiveis={}",
                COD_GRF_OK,
                ok,
                if ilegiveis.is_empty() {
                    "0".to_string()
                } else {
                    ilegiveis.join(",")
                }
            ));
        }
    }

    saida
}

/// Lê o manifesto. `None` = arquivo ausente ou ilegível.
fn ler_manifesto(caminho: &Path) -> Option<Vec<Entrada>> {
    let txt = std::fs::read_to_string(caminho).ok()?;
    let mut v = Vec::new();
    for linha in txt.lines() {
        let c: Vec<&str> = linha.split('|').collect();
        if c.len() >= 5 && c[0] == "f" {
            v.push(Entrada {
                nome: c[1].trim().to_string(),
                modo: c[2].trim().to_string(),
                sha: c[3].trim().to_string(),
            });
        }
    }
    Some(v)
}

/// SHA-256 do **cabeçalho + tabela de arquivos** de uma GRF — o mesmo material
/// que o `rse-manifest` hasheia do outro lado. Os dois têm que concordar byte a
/// byte, então qualquer mudança aqui muda lá também.
fn hash_header_grf(caminho: &Path) -> Result<String, String> {
    // O motivo do erro viaja junto: "nao consegui ler" sem dizer POR QUE manda
    // procurar no lugar errado. Um ERROR_SHARING_VIOLATION (32) aqui significa
    // que o jogo abriu a GRF em modo exclusivo antes de nos — problema de ordem,
    // não de adulteração, e o conserto é outro.
    let mut f = std::fs::File::open(caminho).map_err(|e| format!("open: {}", e))?;
    let tamanho = f.metadata().map_err(|e| format!("metadata: {}", e))?.len();

    let mut cabecalho = [0u8; GRF_HEADER_SIZE];
    f.read_exact(&mut cabecalho)
        .map_err(|e| format!("cabecalho: {}", e))?;
    if &cabecalho[..16] != GRF_MAGIC {
        return Err("magic errado (nao e GRF?)".to_string());
    }

    let offset_tabela = u32::from_le_bytes([
        cabecalho[OFF_TABLE_OFFSET],
        cabecalho[OFF_TABLE_OFFSET + 1],
        cabecalho[OFF_TABLE_OFFSET + 2],
        cabecalho[OFF_TABLE_OFFSET + 3],
    ]) as u64;

    let inicio = GRF_HEADER_SIZE as u64 + offset_tabela;
    if inicio > tamanho {
        return Err(format!(
            "tabela em 0x{:x}, alem do fim ({} bytes)",
            inicio, tamanho
        ));
    }

    f.seek(SeekFrom::Start(inicio))
        .map_err(|e| format!("seek: {}", e))?;
    let mut tabela = Vec::new();
    f.read_to_end(&mut tabela)
        .map_err(|e| format!("tabela: {}", e))?;

    let mut material = Vec::with_capacity(GRF_HEADER_SIZE + tabela.len());
    material.extend_from_slice(&cabecalho);
    material.extend_from_slice(&tabela);
    Ok(to_hex(&sha256(&material)))
}
