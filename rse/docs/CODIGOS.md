# Códigos de violação — o que já existe em código

> **Este arquivo não substitui o `RSE_SPEC.md` §9.** O spec é o documento
> normativo. Este aqui é o espelho do que está *implementado*, mantido junto do
> código para que ninguém precise abrir o spec só para conferir se um código já
> tem dono.
>
> **Antes de criar um código novo, procure nos dois.** Na Fase 6.4 a detecção de
> processos nasceu usando `4001`, que já era `PIPE_TAMPERED` — dois eventos com
> severidade e ação opostas dividindo o mesmo número. Pegou-se antes de subir,
> mas o modo de falhar é silencioso: o log fica ambíguo e ninguém percebe até
> precisar dele.

## Implementados

| Código | Nome | Sev. | Onde | Fase |
|---:|---|---|---|---|
| 1000 | `INTEGRITY_EXE_MISMATCH` | crítica | `integridade.rs` | 5c-2a |
| 1001 | `INTEGRITY_GRF_MISMATCH` | crítica | `integridade.rs` | 5c-2b |
| 1002 | `INTEGRITY_MANIFEST_MISSING` | alta | `integridade.rs` | 5c-2a |
| 2000 | `UNKNOWN_MODULE_LOADED` | média/alta | `modulos.rs` | 6.2 |
| 3000 | `FORBIDDEN_PROCESS` | alta | `processos.rs` | 6.4 |
| 3001 | `DEBUGGER_ATTACHED` | crítica | `deteccoes.rs` | 6.1 |
| 3003 | `REMOTE_HANDLE_WRITE_CAPABLE` | alta | `handles.rs` | 6.4b |
| 3004 | `CLOCK_TAMPERED` | crítica | `relogio.rs` | 6.3 |
| **3002** | **`REMOTE_MEMORY_WRITE`** | **crítica** | **`codigo.rs`** | **6.5** |
| **2003** | **`INLINE_HOOK_DETECTED`** | **alta** | **`codigo.rs`** | **6.5** |
| 4000 | `HEARTBEAT_LOST` | crítica | `canal.rs` (Loader) | 5a |

## Faixa experimental (6000–6999)

Telemetria e sinais em observação. Saem como `info` no servidor — visíveis, sem
virar alerta. **Nada aqui deve virar ação sem antes ganhar um código definitivo.**

| Código | O que é | Onde |
|---:|---|---|
| 6001 | SHA observada de arquivo do manifesto | `integridade.rs` |
| 6002 | exe conferido, sem divergência | `integridade.rs` |
| 6003 | resumo das GRFs conferidas | `integridade.rs` |
| 6010 | a API mentiu em relação ao ntdll (anti-anti-debug) | `deteccoes.rs` |
| 6020 | inventário de módulos do arranque | `modulos.rs` |
| 6030 | handle com escrita cujo dono é esperado (base da máquina ou infra) | `handles.rs` |
| 6031 | linha de base de handles, tirada na 1ª varredura da sessão | `handles.rs` |
| 6040 | relatório truncado: N linhas não couberam no frame | `mensagens.rs` |
| 6050 | razão medida entre as duas fontes de relógio | `relogio.rs` |
| **6060** | **linha de base da vigilância de código** | **`codigo.rs`** |

## Reservados no spec, ainda sem implementação

`2001` `KNOWN_CHEAT_MODULE` · `2002` `IAT_HOOK_DETECTED` ·
`4001` `PIPE_TAMPERED` · `5000` `ENV_VIRTUAL_MACHINE` ·
`5001` `ENV_ELEVATED_MISMATCH`

---

## 3002 e 3003 não são a mesma coisa — e as duas existem

Vale registrar porque a distinção é fácil de perder e cara de recuperar:

| | O que afirma | Evidência |
|---|---|---|
| `3002 REMOTE_MEMORY_WRITE` | alguém **escreveu** na memória do cliente | uma escrita observada |
| `3003 REMOTE_HANDLE_WRITE_CAPABLE` | alguém **pode** escrever | um handle com `VM_WRITE` na tabela do kernel |

A 6.4b implementa o `3003`; a **6.5 implementa o `3002`**, comparando o hash da
seção de código com a foto tirada no arranque.

A distinção deixou de ser teórica quando a 6.4b revelou o seu ponto cego: para
confirmar o dono de um handle é preciso abrir aquele processo, e um processo de
integridade média não abre um elevado — 78% dos donos ficaram inacessíveis numa
máquina real. **Cheat Engine como administrador é invisível para o `3003`.**

O `3002` não tem esse problema, porque não depende de enxergar ninguém: é a
nossa própria memória. Não importa se quem escreveu era administrador ou tinha
driver — se o byte mudou, nós vemos. O que ele *não* pega é quem apenas lê, e aí
quem responde é o `3003`. São complementares de propósito.

Emitir `3002` a partir da evidência do `3003` seria o log afirmando mais do que
se sabe — e é assim que se bane inocente. O antivírus do jogador tem handle com
`VM_WRITE` no cliente e nunca escreveu nada nele.

---

## Pendência

As duas linhas novas (`3003` e `6020`) **ainda não estão no `RSE_SPEC.md` §9**.
Para incorporar, acrescentar à tabela do §9:

```markdown
| 3003 | `REMOTE_HANDLE_WRITE_CAPABLE` | alta | warn + report |
```

e à nota das faixas reservadas, que a 6000–6999 já está em uso por
`6001`–`6003`, `6010`, `6020`, `6030`, `6031`, `6040`, `6050` e `6060`.

> O `6040` é diferente dos outros da faixa: ele não descreve o cliente, descreve
> **o próprio relatório**. Sai com severidade `alta` de propósito — se ele
> aparece, o que você está lendo é uma amostra, não o todo.

---

## O teste que torna esta página menos necessária

`rse/watchdog/src/lib.rs` tem um teste — `codigos::nenhum_codigo_de_violacao_colide`
— que lê os próprios fontes e falha se dois `const COD_*` apontarem para o mesmo
número.

Ele existe porque **as duas colisões da Fase 6 foram pegas por acaso**: a
primeira porque fui conferir o spec por outro motivo, a segunda porque um
arquivo faltando obrigou a olhar o crate inteiro. Nenhuma quebrava a
compilação. Documentação não pega isso — só um teste pega.

Rode `cargo test -p rse-watchdog` antes de commitar um código novo. Esta página
continua útil para saber o que cada número *significa*; o teste cuida de garantir
que cada número tem um dono só.
