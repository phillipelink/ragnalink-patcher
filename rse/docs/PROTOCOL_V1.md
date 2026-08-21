# RSE_PROTOCOL 1 — referência de bytes

Referência rápida do formato na fita. A justificativa de cada decisão está em
`docs/RSE_SPEC.md`; aqui só o suficiente para implementar ou depurar.

**Implementação de referência:** `rse/protocol/` (Rust).
**Vetores congelados:** `rse/protocol/tests/vectors/v1/vectors.txt`.

---

## 1. Ticket — 148 bytes, big-endian

| Offset | Tam. | Campo | Observação |
|---:|---:|---|---|
| 0 | 4 | `magic` | `"RSE1"` = `52 53 45 31` |
| 4 | 1 | `version` | `0x01` |
| 5 | 1 | `flags` | bit0 `strict` · bit1 `vip` · bit2 `staff` |
| 6 | 1 | `key_id` | qual `K_ticket` assinou |
| 7 | 1 | `reserved` | `0`; o receptor aceita qualquer valor **mas ele é assinado** |
| 8 | 8 | `issued_at` | Unix **ms**, UTC |
| 16 | 4 | `ttl_ms` | normalmente `30000` |
| 20 | 16 | `nonce` | CSPRNG — chave do cache de replay |
| 36 | 16 | `session_id` | sessão do Loader |
| 52 | 32 | `machine_fp` | hash com pepper do servidor |
| 84 | 32 | `client_hash` | SHA-256 do manifesto de integridade |
| 116 | 32 | `hmac` | `HMAC-SHA256(K_ticket, bytes[0..116])` |

Região assinada: **`[0, 116)`** — tudo menos o próprio HMAC.

### Ordem da validação (não é estilo, é segurança)

```
1. len == 148                                     -> INVALID_LENGTH
2. magic == "RSE1"                                -> BAD_MAGIC
3. version aceita (N ou N-1)                      -> BAD_VERSION
4. key_id conhecido                               -> UNKNOWN_KEY
5. 0 < ttl_ms <= 120000                           -> BAD_TTL
6. HMAC confere (comparação em tempo constante)   -> BAD_SIGNATURE
7. now <= issued_at + ttl_ms                      -> EXPIRED
8. issued_at <= now + 5000                        -> FUTURE
9. nonce inédito -> grava no cache                -> REPLAY
```

O passo 9 vem **depois** do 6. Gravar o nonce antes de conferir a assinatura
deixaria qualquer um encher o cache do login-server com tickets forjados.

### Códigos de erro (log e telemetria)

| Código | Rótulo | Código | Rótulo |
|---:|---|---:|---|
| 1 | `INVALID_LENGTH` | 6 | `EXPIRED` |
| 2 | `BAD_MAGIC` | 7 | `FUTURE` |
| 3 | `BAD_VERSION` | 8 | `REPLAY` |
| 4 | `UNKNOWN_KEY` | 9 | `BAD_TTL` |
| 5 | `BAD_SIGNATURE` | | |

Faixa 101–199 é do canal Loader↔DLL, para que um código em log nunca seja
ambíguo. Números e rótulos são **congelados**: nunca renumerar, só acrescentar
no fim.

---

## 2. Packet `0x0AAA` — 152 bytes

```
offset  tam  campo
     0    2  0xAA 0x0A     header (little-endian, como todo packet RO)
     2    2  0x98 0x00     packet_len = 152
     4  148  ticket        big-endian internamente
```

> ⚠️ **Dois formatos encaixados.** O envelope é little-endian; o ticket dentro
> dele é big-endian. É o erro mais provável de quem for portar isto para C++.

Enviado **antes** do packet de login (`0x0064`/`0x0825`/…) na mesma conexão TCP.
O packet de login segue byte a byte inalterado.

---

## 3. Frame do canal Loader ↔ DLL

| Offset | Tam. | Campo |
|---:|---:|---|
| 0 | 2 | `magic` = `"RS"` |
| 2 | 1 | `version` = 1 |
| 3 | 1 | `opcode` |
| 4 | 4 | `seq` (u32 LE, monotônico por direção, começa em 1) |
| 8 | 2 | `payload_len` (u16 LE, ≤ 8192) |
| 10 | 2 | `flags` (reservado, 0) |
| 12 | 12 | `nonce` |
| 24 | N | `ciphertext` |
| 24+N | 16 | `tag` (AES-256-GCM) |

- **AAD** = bytes `[0, 12)`.
- **Nonce** = `salt(4) ‖ seq(8, LE)`, com `salt` = `"L2D\0"` ou `"D2L\0"`.
  Determinístico: o receptor recalcula e exige que bata.
- Tamanho total = `24 + payload_len + 16`.

### Opcodes

| Cód. | Nome | Direção | Cód. | Nome | Direção |
|---:|---|---|---:|---|---|
| `0x01` | `HELLO` | L→D | `0x21` | `TICKET_RSP` | L→D |
| `0x02` | `HELLO_ACK` | D→L | `0x30` | `REPORT` | D→L |
| `0x10` | `HEARTBEAT` | D→L | `0x31` | `REPORT_ACK` | L→D |
| `0x11` | `HEARTBEAT_ACK` | L→D | `0x40` | `POLICY` | L→D |
| `0x20` | `TICKET_REQ` | D→L | `0x7F` | `SHUTDOWN` | ambas |

Opcode desconhecido: **registrar e ignorar o frame**. Nunca derrubar a conexão —
é o que permite acrescentar opcode novo sem quebrar quem ainda não atualizou.

### Chaves do canal

```
K_l2d = HKDF-SHA256(ikm = K_s, salt = session_id, info = "RSE1 loader->dll")[0..32]
K_d2l = HKDF-SHA256(ikm = K_s, salt = session_id, info = "RSE1 dll->loader")[0..32]
```

Os textos de `info` fazem parte do formato. Mudá-los quebra quem já está em campo.

---

## 4. Tempos

| Constante | Valor |
|---|---:|
| TTL padrão do ticket | 30 000 ms |
| Tolerância de relógio | 5 000 ms |
| TTL máximo aceito | 120 000 ms |
| Heartbeat (DLL → Loader) | 5 000 ms |
| Prazo do `HEARTBEAT_ACK` | 2 000 ms |
| Heartbeats perdidos até derrubar | 3 |
| Prazo do `HELLO_ACK` após injeção | 5 000 ms |

---

## 5. Vetores de teste

`rse/protocol/tests/vectors/v1/vectors.txt` — **texto simples, não JSON**, porque
quem vai lê-lo do outro lado é o login-server do rAthena, em C++, e ele não tem
parser JSON à mão.

```
#                       comentário
@meta   k=v ...         parâmetros do protocolo e offsets
@key    id=N hex=...    chave de assinatura dos vetores
@ticket name=... now_ms=... twice=0|1 expect=OK|<RÓTULO> hex=...
@packet id=... len=... hex=...
@canal  session_key=... session_id=... k_l2d=... k_d2l=...
@frame  name=... dir=L2D seq=N opcode=N payload_len=N payload=... frame=...
```

Uma linha por registro, `chave=valor` separado por espaço, bytes em hexadecimal
minúsculo. `payload=-` significa payload vazio. Nenhum valor contém espaço, então
não existe questão de escape — dá para ler com `istringstream` em umas dez linhas.

`twice=1` manda apresentar o **mesmo** ticket duas vezes ao mesmo verificador; o
resultado esperado é o da **segunda** vez.

### O que a implementação C++ da Fase 3 precisa reproduzir

Todos os 16 casos de `@ticket`, os 5 `@frame`, a derivação HKDF do `@canal` e a
leitura do `@packet`. Se os dois lados passam nos mesmos casos — inclusive os
negativos e os de borda — eles concordam sobre o formato.

Regenerar os vetores:

```
cargo run --example gen_vectors -- rse/protocol/tests/vectors/v1/vectors.txt
```

A saída é determinística: rodar de novo sem mexer no código não produz diff. Se
produzir, o formato mudou e **todo mundo em campo precisa saber** — o que
significa incrementar `RSE_PROTOCOL`.

---

## 6. Casos de borda que costumam divergir entre implementações

Estão nos vetores de propósito, porque são exatamente onde duas implementações
do mesmo documento discordam:

| Caso | Resultado correto |
|---|---|
| `now == issued_at + ttl_ms` | **OK** — a borda ainda vale (`<=`, não `<`) |
| `now == issued_at + ttl_ms + 1` | `EXPIRED` |
| `issued_at == now + 5000` | **OK** — a tolerância inteira é aceita |
| `issued_at == now + 5001` | `FUTURE` |
| `ttl_ms == 0` | `BAD_TTL` |
| `ttl_ms == 120000` | aceito |
| `ttl_ms == 120001` | `BAD_TTL` |
| `key_id` desconhecido | `UNKNOWN_KEY` — **antes** de calcular HMAC |
| Frame com payload de 0 byte | válido |
| Frame com payload de 8192 bytes | válido |
| Frame com payload de 8193 bytes | `PAYLOAD_TOO_LARGE` |
| `seq` pulando pra frente (1 → 3) | permitido |
| `seq` voltando (3 → 2) | `REPLAYED_SEQUENCE` |
