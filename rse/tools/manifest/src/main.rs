//! `rse-manifest` — gera o manifesto de integridade do cliente (Fase 5c-2b).
//!
//! ```text
//! cargo run -p rse-manifest -- "D:\DEV Ragnarok\ClienteRagnaLinK"
//! ```
//!
//! # Por que esta ferramenta roda na SUA maquina, e nao aqui do lado
//!
//! O `data.grf` do RagnaLinK tem ~3,8 GB. Manifesto se gera onde os arquivos
//! estao — na maquina de quem publica o cliente. A saida (`rse_manifest.txt`) e
//! um texto de poucos KB que acompanha o patch.
//!
//! # Os dois modos, e por que nao existe um so
//!
//! | modo | o que le | para que |
//! |---|---|---|
//! | `full` | o arquivo inteiro | o `.exe` (12 MB) — decisao forte, custo baixo |
//! | `header_only` | cabecalho + tabela de arquivos da GRF | GRF de GB — le alguns MB |
//!
//! Fazer SHA-256 de 3,8 GB a cada clique em JOGAR adicionaria dezenas de
//! segundos, e o jogador acharia que travou. O `header_only` resolve porque
//! **toda** ferramenta de edicao de GRF (GRF Editor e afins) **reconstroi a
//! tabela de arquivos** ao salvar: trocar, acrescentar ou remover qualquer
//! arquivo muda offset, tamanho ou nome de entrada — e portanto muda o hash da
//! tabela. Pega a adulteracao real por alguns MB de leitura.
//!
//! **O que o `header_only` NAO pega, dito com todas as letras:** alguem que
//! sobrescreva o conteudo de um arquivo *no lugar*, mantendo tamanho comprimido
//! e offset identicos. E bem mais dificil do que usar um editor, mas e possivel.
//! Fechar isso e o modo `sampled` (blocos amostrados por sessao), previsto no
//! RSE_SPEC §7 e ainda nao implementado.
//!
//! # E a limitacao maior, que nenhum modo resolve sozinho
//!
//! O manifesto e um arquivo de texto na maquina do jogador. Quem adultera a GRF
//! pode rodar esta mesma ferramenta e gerar um manifesto que combine. O que
//! fecha isso e **amarrar o manifesto ao ticket** (`client_hash` = SHA-256 do
//! manifesto, decidido pelo servidor a partir do `patch_index`, e nao ecoado do
//! cliente). Enquanto isso nao existe, a integridade e **deteccao honesta de
//! adulteracao casual**, nao barreira contra adversario dedicado — e o modo
//! report do servidor esta coerente com isso.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rse_protocol::crypto::{sha256, to_hex};

/// Cabecalho GRF: `"Master of Magic\0"` (16) + chave (14) + offset da tabela (4)
/// + seed (4) + contagem (4) + versao (4). Mesmos numeros que o `gruf/` do
/// launcher usa para ler as GRFs — a fonte da verdade e ele.
const GRF_MAGIC: &[u8; 16] = b"Master of Magic\0";
const GRF_HEADER_SIZE: usize = 46;
/// Offset do campo `file_table_offset` dentro do cabecalho.
const OFF_TABLE_OFFSET: usize = 30;

fn main() {
    let pasta = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    if !pasta.is_dir() {
        eprintln!("erro: {} nao e uma pasta", pasta.display());
        std::process::exit(2);
    }

    let mut linhas: Vec<String> = Vec::new();
    linhas.push("# RagnaShield Engine — manifesto de integridade".to_string());
    linhas.push("# Formato: f|<nome>|<modo>|<sha256>|<size>. Linhas sem f| sao ignoradas.".to_string());
    linhas.push("# Gerado por rse-manifest. NAO edite a mao: a DLL confere contra isto.".to_string());
    linhas.push("v|2".to_string());

    let mut erros = 0usize;
    let mut entradas = 0usize;

    // Varre a pasta: .exe em modo full, .grf em modo header_only. A ordem e
    // alfabetica para a saida ser deterministica — rodar duas vezes sem mexer em
    // nada tem que dar o MESMO arquivo, senao nao da para versionar.
    let mut arquivos: Vec<PathBuf> = match std::fs::read_dir(&pasta) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(e) => {
            eprintln!("erro: nao consegui ler {}: {}", pasta.display(), e);
            std::process::exit(2);
        }
    };
    arquivos.sort();

    for caminho in &arquivos {
        if !caminho.is_file() {
            continue;
        }
        let nome = match caminho.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let ext = caminho
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let resultado = match ext.as_str() {
            "exe" => Some(hash_full(caminho).map(|(h, s)| ("full", h, s))),
            "grf" => Some(hash_header_grf(caminho).map(|(h, s)| ("header_only", h, s))),
            _ => None,
        };

        match resultado {
            None => {}
            Some(Ok((modo, hash, size))) => {
                println!("  {:<28} {:<12} {}", nome, modo, &hash[..16]);
                linhas.push(format!("f|{}|{}|{}|{}", nome, modo, hash, size));
                entradas += 1;
            }
            Some(Err(e)) => {
                eprintln!("  {:<28} FALHOU: {}", nome, e);
                erros += 1;
            }
        }
    }

    if entradas == 0 {
        eprintln!("erro: nenhum .exe ou .grf encontrado em {}", pasta.display());
        std::process::exit(2);
    }

    let destino = pasta.join("rse_manifest.txt");
    let corpo = format!("{}\n", linhas.join("\n"));
    if let Err(e) = std::fs::write(&destino, corpo) {
        eprintln!("erro: nao consegui escrever {}: {}", destino.display(), e);
        std::process::exit(2);
    }

    println!();
    println!("{} entrada(s) escritas em {}", entradas, destino.display());
    if erros > 0 {
        // Manifesto incompleto e pior do que manifesto ausente: a DLL conferiria
        // so uma parte e diria que esta tudo bem. Saida != 0 para um script de
        // publicacao perceber.
        eprintln!("ATENCAO: {} arquivo(s) falharam e ficaram DE FORA do manifesto", erros);
        std::process::exit(1);
    }
}

/// SHA-256 do arquivo inteiro, em blocos (nao carrega tudo em memoria).
fn hash_full(caminho: &Path) -> Result<(String, u64), String> {
    let mut f = std::fs::File::open(caminho).map_err(|e| e.to_string())?;
    let tamanho = f.metadata().map_err(|e| e.to_string())?.len();

    // O `sha256` do protocolo recebe uma fatia; para arquivo grande juntamos em
    // memoria por partes. O `.exe` tem 12 MB, entao isto e seguro aqui — e o
    // caminho de GRF nem passa por esta funcao.
    let mut dados = Vec::with_capacity(tamanho as usize);
    f.read_to_end(&mut dados).map_err(|e| e.to_string())?;
    Ok((to_hex(&sha256(&dados)), tamanho))
}

/// SHA-256 do **cabecalho + tabela de arquivos** de uma GRF.
///
/// Le `[0, 46)` e `[46 + file_table_offset, EOF)`. Nada do corpo dos arquivos —
/// e por isso que funciona numa GRF de 3,8 GB sem o jogador achar que travou.
fn hash_header_grf(caminho: &Path) -> Result<(String, u64), String> {
    let mut f = std::fs::File::open(caminho).map_err(|e| e.to_string())?;
    let tamanho = f.metadata().map_err(|e| e.to_string())?.len();

    let mut cabecalho = [0u8; GRF_HEADER_SIZE];
    f.read_exact(&mut cabecalho)
        .map_err(|_| "arquivo menor que o cabecalho GRF".to_string())?;
    if &cabecalho[..16] != GRF_MAGIC {
        return Err("nao parece uma GRF (magic errado)".to_string());
    }

    let offset_tabela = u32::from_le_bytes([
        cabecalho[OFF_TABLE_OFFSET],
        cabecalho[OFF_TABLE_OFFSET + 1],
        cabecalho[OFF_TABLE_OFFSET + 2],
        cabecalho[OFF_TABLE_OFFSET + 3],
    ]) as u64;

    let inicio_tabela = GRF_HEADER_SIZE as u64 + offset_tabela;
    if inicio_tabela > tamanho {
        return Err(format!(
            "tabela de arquivos aponta para 0x{:x}, alem do fim ({} bytes)",
            inicio_tabela, tamanho
        ));
    }

    f.seek(SeekFrom::Start(inicio_tabela))
        .map_err(|e| e.to_string())?;
    let mut tabela = Vec::new();
    f.read_to_end(&mut tabela).map_err(|e| e.to_string())?;

    let mut material = Vec::with_capacity(GRF_HEADER_SIZE + tabela.len());
    material.extend_from_slice(&cabecalho);
    material.extend_from_slice(&tabela);
    Ok((to_hex(&sha256(&material)), tamanho))
}
