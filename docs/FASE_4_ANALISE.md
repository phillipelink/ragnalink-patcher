# Fase 4 — Leitura do launcher antes de escrever código

**Relatório técnico** · 21/08/2026 · **Nada implementado ainda**

---

## Resumo

Reli o caminho que abre o Ragexe hoje. **Dois achados invalidam parte do plano da Fase 4**,
e é melhor descobrir agora do que com o Loader meio escrito:

1. O launcher abre o jogo com `ShellExecuteExW` + verbo **`runas`** — ou seja, **com
   elevação**. O plano previa `CreateProcessW(CREATE_SUSPENDED)` no Loader, e
   `CreateProcessW` **não sabe elevar**.
2. O **ADR-004** (passar a credencial por *handle herdado*) é **incompatível** com
   `ShellExecuteExW`, que não herda handles. Herança exige `CreateProcess` com
   `bInheritHandles = TRUE`.

Os dois se cruzam: **dá para ter elevação ou handle herdado, não os dois.**

Também confirmei três coisas que **simplificam** a fase — estão na §4.

---

## 1. O caminho real, hoje

```
index.html                    JS: external.invoke("play")
   ↓
ui.rs  invoke_handler         "play" => handle_play(webview)
   ↓
ui.rs  handle_play            client_arguments = config.play.arguments   // ["1sak1"]
   ↓
ui.rs  start_game_client      exit_on_success = config.play.exit_on_success // true
   ↓
process.rs start_executable   junta os argumentos numa String
   ↓
process.rs win32_spawn_process_runas
   ↓
   ShellExecuteExW { lpVerb: "runas", lpFile: <exe absoluto>, lpParameters: <args> }
   ↓
   RagnaLinK_ptBR5.exe  (ELEVADO)
   ↓
ui.rs                         webview.exit()   // o launcher fecha imediatamente
```

O trecho que decide tudo, em `process.rs`:

```rust
let operation = to_u16s("runas")?;           // <- pede elevação
let mut execute_info = SHELLEXECUTEINFOW {
    fMask: SEE_MASK_CLASSNAME,               // <- SEM SEE_MASK_NOCLOSEPROCESS
    ...
    hProcess: ptr::null_mut(),               // <- nenhum handle volta
};
```

---

## 2. Achado 1 — `CreateProcessW` não eleva

`CreateProcessW` cria o filho **com o token do pai**. Não existe flag de elevação: quem
eleva no Windows é o `ShellExecuteEx` com o verbo `runas`, porque quem mostra o diálogo do
UAC é o serviço AppInfo, não a API de criação de processo.

Consequência direta para o desenho previsto:

| Quem cria o Ragexe | Nível do Ragexe | Injeção da DLL funciona? |
|---|---|---|
| Hoje: launcher via `runas` | **elevado** | — (não há DLL hoje) |
| Loader **não** elevado via `CreateProcessW` | médio | sim (mesmo nível) |
| Loader **elevado** via `CreateProcessW` | **elevado** | sim (mesmo nível) |
| Loader não elevado → processo elevado | — | **não**, barreira de integridade |

Ou seja, o Loader e o Ragexe **têm que estar no mesmo nível de integridade**, senão a
injeção da Fase 5 não acontece. E se o Loader não for elevado, o Ragexe deixa de ser — que
é uma **mudança de comportamento** para todo jogador cujo cliente precise escrever em pasta
protegida.

---

## 3. Achado 2 — handle herdado não sobrevive ao `ShellExecuteEx`

O ADR-004 escolheu passar a credencial de sessão por **handle herdado** justamente para ela
não aparecer em `wmic process get commandline`. O objetivo continua certo; o mecanismo não
funciona aqui.

Herança de handle exige:

```c
CreateProcessW(..., /* bInheritHandles */ TRUE, ...)
```

O `ShellExecuteExW` passa pelo shell e **não** oferece isso. Então:

- Se o launcher chamar o Loader por `ShellExecuteExW` (para elevar), **não há handle
  herdado** — o ADR-004 cai.
- Se chamar por `CreateProcessW` (para herdar), **não há elevação** — o achado 1 morde.

### Alternativas para a credencial, comparadas

| Mecanismo | Some do `commandline`? | Atravessa elevação? | Custo |
|---|---|---|---|
| Handle herdado (ADR-004) | sim | **não** | exige `CreateProcessW` |
| **Named pipe** criado pelo launcher | sim | **sim** | o pipe já existe no desenho |
| Variável de ambiente | sim (mas visível no Process Explorer) | sim | trivial, e mais fraco |
| Arquivo temporário com ACL | sim | sim | pior de todos — toca o disco |

O **named pipe** resolve os dois problemas de uma vez, e não é peça nova: a Fase 4 já
precisa de um pipe para o heartbeat. Sobre a direção de integridade, a política obrigatória
do Windows é *no-write-up*: um processo de integridade **alta** pode abrir um objeto criado
por um processo de integridade **média**. Loader elevado lendo pipe criado pelo launcher
comum, portanto, **funciona**.

---

## 4. Três coisas que simplificam a fase

**4.1 O launcher não manipula a senha do jogador.** O botão JOGAR chama `handle_play`, que
passa apenas `config.play.arguments` — hoje `["1sak1"]`. Existe um `handle_login` herdado do
rpatchur original que montaria `-t:<senha> <login> server`, mas a interface do RagnaLinK
**não o usa**: o login acontece dentro do jogo. Isso mantém o ADR-002 verdadeiro e significa
que a **credencial do RSE é o único segredo** que atravessa para o Loader.

**4.2 Não há comportamento de "esperar o filho" a preservar.** O `SEE_MASK_NOCLOSEPROCESS`
não está ligado e o `hProcess` volta nulo — o launcher nunca teve handle do jogo. Com
`exit_on_success: true` ele fecha logo depois. Uma restrição a menos.

**4.3 O `"1sak1"` é dado de configuração, não código.** Vive no `RagnaLinK.yml`, em
`play.arguments`. O Loader só precisa **repassar a lista intacta** — não interpreta nada. O
critério de aceite "o `1sak1` chega intacto" vira uma asserção simples.

> ⚠️ Um detalhe achado de passagem, **não** relacionado ao RSE: o `win32_spawn_process_runas`
> resolve o executável com `std::env::current_dir()?.join(path)` — a partir do **diretório de
> trabalho**, não da pasta do executável. Aberto pelo Explorer os dois coincidem; por um
> atalho com "Iniciar em" diferente, não. É a mesma classe do bug de `index_url` que já foi
> corrigido. Fica registrado; não é para mexer nesta fase.

---

## 5. Proposta

### Desenho escolhido: **Loader elevado, credencial por pipe**

```
launcher (médio)
  │ 1. POST /rse/v1/session          -> credencial de sessão
  │ 2. cria named pipe  \\.\pipe\rse-<aleatório>   (DACL: só o usuário atual)
  │ 3. ShellExecuteExW("runas", rse_loader.exe, "--pipe rse-<aleatório> -- 1sak1")
  │                                     ^ o UAC aparece aqui, uma vez
  │ 4. espera o Loader conectar e ler (timeout), ENTÃO webview.exit()
  ↓
Loader (elevado)
  │ 5. conecta no pipe, lê a credencial
  │ 6. POST /rse/v1/ticket           -> ticket de 30 s
  │ 7. CreateProcessW(CREATE_SUSPENDED, RagnaLinK_ptBR5.exe, "1sak1")   [elevado]
  │ 8. injeta a rse_watchdog.dll  (Fase 5)
  │ 9. ResumeThread só depois do HELLO_ACK
  ↓
Ragexe (elevado) — igual a hoje
```

**Por que esta e não a outra.** O princípio deste projeto desde a Fase 1 é não mudar o que
já funciona. Hoje o jogador vê **um** diálogo de UAC ao clicar em JOGAR; neste desenho ele
continua vendo **um**, só que do Loader. O Ragexe continua elevado, então nenhum cliente
instalado em pasta protegida quebra. E a injeção da Fase 5 fica no mesmo nível de
integridade, que é o único jeito de ela funcionar.

### O que muda nos documentos

| Documento | Mudança |
|---|---|
| `ARCHITECTURE.md` ADR-004 | de *handle herdado* para **credencial pelo pipe de controle**, com o porquê |
| `ARCHITECTURE.md` §3.1 L4 | o contrato continua válido; o que muda é o miolo do `rse.rs` |
| `RSE_SPEC.md` | acrescentar o quadro do pipe launcher↔Loader (`CREDENTIAL`) |
| `ROADMAP.md` Fase 4 | trocar "leitura da credencial pelo handle herdado" pela forma nova |

### Detalhe que quase passou

O `exit_on_success: true` faz o launcher fechar **imediatamente** depois de disparar o jogo.
Com a credencial vindo pelo pipe, isso vira corrida: se o launcher morrer antes de o Loader
conectar, a credencial se perde e o jogo não abre. O passo 4 acima existe por causa disso —
o launcher **espera a leitura** (com prazo curto e um caminho de erro visível na interface)
antes de sair.

### Ainda em aberto, e depende de você

| # | Pergunta | Por que importa |
|---|---|---|
| **P1** | O cliente precisa mesmo de elevação? | Se não precisar, dá para largar o `runas` e o jogador **para de ver UAC**. Melhor UX, mas é mudança de comportamento |
| **P2** | O `rse.enabled: false` mantém o `runas` de hoje? | Sim, por definição — o critério de aceite exige comportamento idêntico |
| **P3** | Certificado de assinatura (D6) | Sem ele, um `.exe` novo pedindo elevação é candidato forte a alerta de antivírus |

---

## 6. Nada foi alterado

Nenhum arquivo do launcher foi tocado. Este documento existe para a decisão da §5 ser
tomada **antes** de o Loader existir — trocar o mecanismo de credencial com o Loader escrito
custaria bem mais.
