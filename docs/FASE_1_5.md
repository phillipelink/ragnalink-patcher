# Fase 1.5 — Destravar a toolchain

**Relatório técnico e plano de execução**
**Data:** 21/08/2026 · **Estado:** ✅ **Passo A concluído e validado no Windows** — ver §0.
O Passo B tem um bloqueio conhecido: §4b.

---

## 0. ✅ Passo A concluído — 21/08/2026

O `ntapi` saiu, o launcher foi recompilado e **os quatro testes manuais passaram**.

### O caminho, incluindo o desvio

O Passo A aplicou-se ao `Cargo.lock` sem surpresa: saída idêntica à prevista, `Removing
ntapi v0.3.6` e `Removing miow v0.3.7`, `proc-macro2` intacto em 1.0.26. Mas a compilação
parou em:

```
error: linker `link.exe` not found
```

O `rustup` traz o compilador Rust; o alvo `*-pc-windows-msvc` **linka com o `link.exe` da
Microsoft**. O `vswhere` confirmou que o workload C++ não estava instalado.

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools `
  --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
rustup target add i686-pc-windows-msvc
```

> ⚠️ O `--override` é obrigatório. Sem ele o winget instala só o *bootstrapper* de 4 MB e
> o `link.exe` continua ausente — com a mensagem de erro idêntica, o que engana.

**Isto também explicou um mistério antigo:** é a mesma causa do `cl` não reconhecido quando
tentamos compilar o teste de vetores do emulador. Na ocasião foi atribuído ao emulador
construir por Docker — verdade, mas não era a causa.

### Pré-requisito permanente das Fases 4 e 5

| Fase | Precisa do toolchain C++? |
|---|---|
| 3a / 3b — servidor | não (Linux/Docker) |
| **1.5 — destravar** | **sim** ✅ resolvido |
| **4 — RSE Loader** (`.exe` i686) | **sim** |
| **5 — RSE DLL** (`cdylib` i686) | **sim** |

O alvo `i686-pc-windows-msvc` já foi adicionado, então as Fases 4 e 5 não esbarram nisso.

### Resultado do build

```
Finished release [optimized] target(s) in 1m 15s
```

Compilaram sem erro, na toolchain travada em 1.68.2: `tokio 1.26.0`, `mio 0.8.11`,
`windows-sys 0.45`/`0.48`, `web-view 0.7.3`, `webview-sys 0.6.2` (a parte em C) e
`tinyfiledialogs` — que **ficou em 3.3.10**, exatamente o que o passo cirúrgico preservava.

Os dois avisos (`unused import` em `patcher/core.rs`, `dead_code` em `patching.rs`) são
pré-existentes no código do fork e não vieram desta mudança.

### Teste manual — resultado

Rodado na instalação real (`ClienteRagnaLinK\RagnaLinK.exe`), não em `target\release\`.

> Detalhe que custou um susto: rodar o `rpatchur.exe` direto de `target\release\` dá
> *"Failed to retrieve the patcher's configuration"*. Não é defeito — o launcher deriva o
> nome do YAML do **próprio nome do executável** (`PathBuf::from(patcher_name)
> .with_extension("yml")`). Como `rpatchur.exe`, ele procura `rpatchur.yml`; como
> `RagnaLinK.exe`, acha o `RagnaLinK.yml`. O teste **tem** que ser na instalação real.

| # | Teste | Resultado |
|---|---|---|
| 1 | Patch completo | ✅ *"Tudo atualizado. Bom jogo!"* a 100% |
| 2 | Janela sem moldura e recortada na arte | ✅ sem borda branca; `CreateRectRgn`/`CombineRgn` intactos |
| 3 | Notícias e status do servidor | ✅ carregaram — o `reqwest`, que arrastava o `tokio`, segue funcionando |
| 4 | Minimizar | ✅ |
| 5 | Arrastar pela arte | ✅ |
| 6 | Abrir o jogo (JOGAR) | ✅ chegou na tela de login |

**Nenhuma regressão.** O Passo A está pronto para commit.

---

## 1. O que a trava realmente prende

Confirmado contra o `Cargo.lock` do repositório, resolvendo para
`x86_64-pc-windows-msvc`:

```
ntapi v0.3.6
└── mio v0.7.11
    └── tokio v1.8.4
        ├── rpatchur              (dependência direta)
        ├── reqwest v0.11.3
        ├── hyper v0.14.7
        ├── h2 v0.3.3
        ├── tokio-native-tls v0.3.0
        └── tokio-util v0.6.6
```

A explicação no `rust-toolchain.toml` está **correta em todos os pontos**. Vale registrar
isso: a análise partiu de um comentário confiável, e ele economizou o trabalho de
redescobrir o problema.

Existe uma **segunda árvore** na resolução, e ela confunde quem olha rápido:

```
tokio v0.2.25 ── hyper v0.13.10 ── httptest v0.13.3   [dev-dependency]
```

Essa vem do `httptest`, que é dependência **de teste**. Não entra no `RagnaLinK.exe`. O
`mio 0.6.23` que aparece junto usa `miow 0.2`/`winapi 0.2` e **não** toca no `ntapi` — não
é problema, e não precisa ser mexido nesta fase.

### O estado atual está saudável

Verificado, não presumido:

```
cargo +1.68.2 test -p rse-protocol   ->  52 + 8 + 1 testes, todos verdes
cargo +1.68.2 check -p gruf -p mkpatch  ->  limpo
```

O `Cargo.lock` versionado **não contém** os crates do RSE (a Fase 2 nunca foi resolvida no
Windows). Cheguei a suspeitar que isso já tivesse quebrado a compilação travada — **e
estava errado**: o cargo 1.68 preserva os pinos antigos e encaixa as dependências do RSE em
volta, mantendo `proc-macro2` em 1.0.26. A defasagem é cosmética; some no primeiro build.

---

## 2. Por que **não** começar com `cargo update`

Um `cargo update` sem argumentos resolve o `ntapi`, sim. Mas move **~130 crates**, e três
merecem atenção porque não são código Rust puro:

| Crate | Salto | Por que importa |
|---|---|---|
| `tinyfiledialogs` | 3.3.10 → **3.9.1** | Compila **C**. A 3.9.1 passou a incluir `ShellScalingApi.h` (HiDPI). É dependência direta do `rpatchur` **e** do `web-view`. É o crate das caixas de diálogo |
| `winreg` | 0.7.0 → **0.50.0** | Salto enorme. O `reqwest` usa para detectar proxy no Windows |
| `openssl-sys` | 0.9.63 → 0.9.117 | No Windows o `reqwest` usa schannel, não OpenSSL — mas o crate está na árvore |

Junte a isso `time 0.1 → 0.3`, `syn` passando a conviver em três versões maiores, e o
diagnóstico fica ruim: **se a janela quebrar, você não sabe qual dos 130 quebrou.**

E a pilha gráfica deste projeto é exatamente o que não dá para testar sozinho. O
`web-view 0.7.3` é de 2020, edição 2015, e fala com o MSHTML através do `webview-sys`.
Não existe teste automatizado que prove que a janela sem moldura ainda recorta certo.
Quem prova é você, olhando.

---

## 3. O achado: existe um ponto ideal

Procurando a **maior** versão do `tokio` que elimina o `ntapi` **sem** arrastar
`proc-macro2`/`quote` para além da toolchain travada:

| tokio | ntapi | proc-macro2 | compila em 1.68.2 |
|---|---|---|---|
| 1.16.1 | **sim** (ainda mio 0.7) | 1.0.26 | — |
| 1.17.0 | não | 1.0.26 | sim |
| **1.26.0** | **não** | **1.0.26** | **sim** ← escolhido |
| 1.28.2 | não | 1.0.107 | **não** (exige 1.71) |
| 1.38.2 | não | 1.0.107 | **não** (exige 1.71) |
| 1.53.1 | não | 1.0.107 | **não** (exige 1.71) |

O `tokio 1.26.0` é o teto: a partir do 1.28 o `tokio-macros` vai para a linha 2.x, que puxa
`proc-macro2 1.0.107`, que exige rustc ≥ 1.71.

Isso permite **separar duas coisas que o roadmap tratava como uma só**: tirar o `ntapi` e
trocar de compilador são mudanças independentes, e vale fazê-las em commits diferentes.

---

## 4. Passo A — tirar o `ntapi` sem tocar no compilador

**O comando é este, e é só ele:**

```bash
cargo update -p tokio@1.8.4 --precise 1.26.0
```

Nenhum `Cargo.toml` muda. O `rust-toolchain.toml` **continua** em 1.68.2.

### O que muda no `Cargo.lock`

```
  8 crates com versão alterada
 32 adicionados  (22 são o RSE se acertando + 10 da família windows-sys)
  1 REMOVIDO     <- ntapi
```

| Crate | De | Para |
|---|---|---|
| `tokio` | 1.8.4 | 1.26.0 |
| `mio` | 0.7.11 | 0.8.11 |
| `tokio-macros` | 1.1.0 | 1.8.2 |
| `socket2` | 0.4.0 | 0.4.10 |
| `libc` | 0.2.94 | 0.2.189 |
| `autocfg` | 1.0.1 | 1.5.1 |
| `miow` | 0.3.7 | **removido** |
| `ntapi` | 0.3.6 | **removido** |

O `mio 0.8` troca o `ntapi` pelo `windows-sys 0.48` — que é o caminho **suportado** para
falar com a API do Windows, e declara MSRV **1.48**. Ou seja: a substituição é para uma
dependência mais moderna *e* mais tolerante que a atual.

### O que foi verificado aqui

- `cargo +1.68.2 check -p tokio@1.26.0 -p mio@0.8.11` — compila
- `cargo +1.68.2 test -p rse-protocol` — 61 testes verdes
- `cargo +1.68.2 check -p gruf -p mkpatch` — limpo
- `cargo tree -i ntapi --target x86_64-pc-windows-msvc` — **vazio**

### O que isto tem de bom

O `RagnaLinK.exe` sai deste passo compilado pelo **mesmo compilador de antes**, com o mesmo
`web-view`, o mesmo `winapi`, o mesmo `tinyfiledialogs`. Se a janela mudar de comportamento
depois do Passo A, a causa está num conjunto de 8 crates — não de 130.

---

## 4b. 🚨 Um bloqueio do Passo B, descoberto na Fase 4

Compilando o launcher contra um rustc moderno (1.95), aparece um erro que **nao
existe** na 1.68.2:

```
error[E0061]: this method takes 0 arguments but 1 argument was supplied
   --> rpatchur/src/patcher/core.rs:170:15
    |
170 |     lock_file.try_lock(FileLockMode::Exclusive)?;
    |               ^^^^^^^^ ----------------------- unexpected argument
```

**A causa nao e o codigo do fork — e a biblioteca padrao.** O Rust 1.89 estabilizou
`std::fs::File::try_lock`. Metodo inerente vence metodo de trait na resolucao, entao a
chamada passa a resolver para o `try_lock()` do `std`, que nao recebe argumento, em vez do
`try_lock(FileLockMode)` do crate `advisory_lock`.

Na 1.68.2 o metodo inerente nao existe e tudo funciona. Ou seja: **o Passo A esta a salvo, o
Passo B nao.** Isto foi encontrado por acaso, ao compilar a Fase 4 para conferir o Loader —
e teria aparecido no meio do Passo B, sem contexto.

**Correcao (uma linha), para quando o Passo B acontecer:**

```rust
// Chamada totalmente qualificada: diz explicitamente que se quer o metodo do
// trait, e nao o homonimo que o std ganhou na 1.89.
AdvisoryFileLock::try_lock(&lock_file, FileLockMode::Exclusive)?;
```

A alternativa e migrar para o bloqueio nativo do `std` e remover o `advisory_lock` da
arvore — mais limpo a longo prazo, mas e mudanca de comportamento (o `std` e o crate tratam
`WouldBlock` de formas diferentes) e por isso nao cabe junto de uma troca de compilador.
Uma coisa de cada vez.

---

## 5. Passo B — destravar o compilador

Só depois do Passo A estar testado e commitado.

1. Apagar o `rust-toolchain.toml` (ou fixá-lo numa estável recente com um novo *porquê*
   escrito — a segunda opção é melhor: build reproduzível continua valendo)
2. `cargo update`
3. Compilar em `i686-pc-windows-msvc` **e** `x86_64-pc-windows-msvc`
4. Rodar o teste manual da §7 — **este passo não é opcional**

**A MSRV do destino é 1.71**, pelo `tokio 1.53`, `mio 1.2.2` e `tokio-util 0.7.19`.

### Uma correção ao roadmap

O roadmap dizia que a Fase 4 exigiria destravar porque *"o ecossistema moderno é o
`windows`/`windows-sys` — MSRV ≥ 1.70"*. Medindo:

| windows-sys | MSRV declarada |
|---|---|
| 0.48.0 | 1.48 |
| 0.52.0 | 1.56 |
| 0.61.2 | 1.71 |

Ou seja: dava para escrever o Loader com `windows-sys 0.52` **sem** destravar nada. A trava
não era um bloqueio absoluto para a Fase 4 — era um teto que empurraria você para versões
antigas de tudo. Destravar continua sendo a decisão certa, mas por conforto e manutenção, e
não por impossibilidade. Vale corrigir o registro.

---

## 6. O que **não** consegui verificar daqui, e por quê

Sendo direto, porque isto muda o que você precisa fazer:

| Verificação | Estado | Motivo |
|---|---|---|
| Resolução de dependências | ✅ feita | independente de plataforma |
| `tokio`/`mio` compilam em 1.68.2 | ✅ feita | crates multiplataforma |
| `rse-protocol`, `gruf`, `mkpatch` | ✅ feita | não tocam Windows API |
| `rpatchur` compila para MSVC | ❌ **não** | `tinyfiledialogs` compila C e precisa do `lib.exe`/SDK da Microsoft |
| `rpatchur` compila para GNU | ❌ **não** | o mingw não tem `ShellScalingApi.h` |
| `web-view` + MSHTML funcionam | ❌ **não** | precisa de Windows de verdade, com tela |

As três últimas são **suas**. Não há atalho: a pilha gráfica só se prova rodando.

---

## 7. Teste manual — o roteiro

Vale para o Passo A e, de novo, para o Passo B. Sempre com o **executável de release**,
nunca o de debug: o `panic = 'abort'` e o `lto = true` do perfil de release mudam
comportamento, e é o release que vai para o jogador.

```bash
cargo build --release --target i686-pc-windows-msvc -p rpatchur
```

| # | Passo | O que observar |
|---|---|---|
| 1 | Apagar a pasta de destino e rodar um **patch do zero** | Barra de progresso anda, todos os patches aplicam, sem erro no fim |
| 2 | Rodar de novo, já atualizado | Reconhece que não há nada a fazer — não repatcheia |
| 3 | Olhar a janela | **Sem moldura**, recortada no formato da arte, sem retângulo branco nas bordas |
| 4 | Botão de minimizar | Minimiza mesmo (é `winuser` chamado pelo JS) |
| 5 | Arrastar pela área da arte | A janela acompanha o mouse |
| 6 | Botão de fechar | Fecha limpo, sem processo órfão no Gerenciador de Tarefas |
| 7 | Abrir o jogo pelo launcher | Ragexe sobe e **chega na tela de login** |
| 8 | Propriedades do `RagnaLinK.exe` | "Atualizador do RagnaLinK", empresa RagnaLinK — o `winres` ainda funciona |

Os passos **3, 4 e 5** são os que a Fase 1.5 pode quebrar sem avisar: são exatamente os que
dependem do `web-view` conversando com o MSHTML. O passo 7 é o que confirma que o
`"1sak1"` continua chegando inteiro no Ragexe.

Se qualquer um falhar no Passo B mas passar no Passo A, o culpado é o compilador novo ou um
dos ~130 crates — e aí dá para bissectar, porque os dois commits estão separados.

---

## 8. Riscos

| Risco | Probabilidade | O que fazer |
|---|---|---|
| `tinyfiledialogs 3.9.1` quebra o build MSVC | média (só no Passo B) | Fixar em `--precise 3.3.10`; nada no launcher depende do que a 3.9 adicionou |
| `web-view 0.7.3` não compila em rustc moderno | média | É edição 2015, sem manutenção desde 2020. Se acontecer, o Passo A já entregou o essencial e o Passo B pode esperar |
| Recorte da janela muda de comportamento | baixa | `wingdi`/`winapi 0.3` não mudam no Passo A |
| Regressão silenciosa no patch | baixa | Passo 1 do roteiro cobre |

**Plano de recuo:** os dois passos são commits separados sobre o `Cargo.lock`. Reverter é
`git revert` de um commit e recompilar — não há migração de dados nem estado no meio.

---

## 9. Recomendação

Fazer o **Passo A agora** e commitá-lo sozinho, com o roteiro da §7 rodado. É uma mudança
de 8 crates que remove o motivo original da trava e mantém tudo o mais idêntico.

O **Passo B** é uma decisão separada, e ela pode esperar o começo da Fase 4 — quando você
souber qual API do Windows o Loader vai usar de fato, e portanto qual MSRV precisa mesmo.
Destravar sem ter esse número é otimizar no escuro.
