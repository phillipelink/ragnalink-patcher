# Como lançar uma atualização do cliente — RagnaLinK

Roteiro do dia a dia: você mexeu em alguma coisa do cliente (sprite, textura, lua,
tradução) e quer que os jogadores recebam. Nada aqui exige push no site nem deploy.

---

## Regra de ouro, antes de tudo

**Índice publicado nunca se reaproveita nem se reordena.**

O patcher grava no `RagnaLinK.dat` o último índice que aplicou e só baixa o que for
**maior** que ele. Se você apagar o patch `2` e republicar outro arquivo como `2`, quem
já atualizou nunca vai receber — e não aparece aviso nenhum, nem pra você nem pro
jogador. Errou num patch? Publica o próximo índice corrigindo. Nunca mexe no passado.

---

## Passo 1 — Montar a pasta-fonte

Crie uma pasta com **só o que mudou**, espelhando a estrutura de dentro da GRF:

```
E:\DEV Ragnarok\Patch\007\
└── data\
    ├── sprite\...\meu_chapeu.spr
    ├── sprite\...\meu_chapeu.act
    └── texture\interface\algo.bmp
```

Vale versionar essas pastas no git (são pequenas e ficam auditáveis). O `.thor`
gerado é que não entra no repositório.

## Passo 2 — Ajustar o `patch.yml`

Copie o modelo de `ragnalink\patch.yml` pra dentro da pasta do patch e liste o que entra:

```yaml
use_grf_merging: true          # true = entra na GRF | false = escreve solto na pasta do jogo
target_grf_name: ragnalink.grf
include_checksums: true        # NÃO TIRE - ver o aviso embaixo

entries:
  # Pasta inteira (percorre tudo que estiver dentro, recursivo)
  - relative_path: data\sprite

  # Arquivo único
  - relative_path: data\texture\interface\algo.bmp

  # Apagar algo que já foi distribuído
  - relative_path: data\texture\errado.bmp
    is_removed: true

  # Guardar num caminho diferente do que está no disco
  - relative_path: fonte\clientinfo.xml
    in_grf_path: data\clientinfo.xml
```

Os caminhos usam **barra invertida**, como dentro da GRF.

### `use_grf_merging: false` — quando usar
Para o que **não mora na GRF**: `System\`, o `opensetup.exe`, o `DATA.INI`, o próprio
executável do jogo. Nesse caso o conteúdo é escrito solto na pasta do cliente. Como é
uma chave do arquivo inteiro, um patch é **ou** de GRF **ou** de pasta — mexeu nos dois,
gera dois `.thor` com índices seguidos.

### ATENÇÃO: `include_checksums: true` não é opcional na prática
O `RagnaLinK.yml` está com `check_integrity: true`. Só que se o `.thor` for gerado **sem**
checksums, o patcher abre, não encontra o arquivo de integridade e **considera o pacote
válido** (`is_archive_valid` devolve `Ok(true)` quando o erro é `EntryNotFound`).

Ou seja: esquecer essa linha não dá erro — apenas **desliga a verificação em silêncio**,
e um download truncado seria aplicado direto dentro da GRF do jogador. Sempre `true`.

## Passo 3 — Gerar o `.thor`

```
mkpatch.exe patch.yml -p "E:\DEV Ragnarok\Patch\007" -o ragnalink_007.thor
```

- `-p` = pasta que contém os dados (padrão: pasta atual)
- `-o` = arquivo de saída (padrão: nome do yml com extensão `.thor`)
- `-v` = mostra arquivo por arquivo, útil pra conferir se pegou tudo

Nomeie o arquivo com o índice. Não é obrigatório, mas quando tiver 40 patches
publicados você vai agradecer.

## Passo 4 — Testar ANTES de publicar

O patcher tem o botão **Patch manual** justamente pra isso: ele aplica um `.thor` do
disco sem passar pelo servidor. Use numa **cópia** do cliente, porque a aplicação é real
e mexe na GRF de verdade.

Confira no jogo se a mudança apareceu. Só então publique.

Para repetir um teste, apague o `RagnaLinK.dat` (o cache do último índice aplicado) —
ou chame `reset_cache` pela interface.

## Passo 5 — RagnaShield: manifesto e lista (ANTES de publicar)

> 🚨 **Pule este passo e você tranca jogador do lado de fora.** Não é aviso de estilo: com
> `rse_enforce: on`, quem não recebe ticket não loga, e o ticket depende do manifesto bater
> com a lista do servidor.

### Por que quase todo patch precisa disto

O RagnaShield confere a integridade do cliente contra o `rse_manifest.txt`, e as GRFs são
conferidas por **cabeçalho + tabela de arquivos**. Entrar com um patch numa GRF **reescreve
essa tabela** — então o hash muda. Na prática:

| O patch mexe em… | Precisa refazer o manifesto? |
|---|---|
| conteúdo dentro de uma GRF (`use_grf_merging: true`) | **sim** |
| `.exe` do jogo, do launcher ou do opensetup | **sim** |
| arquivo solto que não é `.exe` (System\, DATA.INI, tradução solta) | não |

### A ordem, e por que ela é essa

```
1. aplica o patch numa copia de referencia do cliente   (o Passo 4 ja faz isto)
2. gera o manifesto A PARTIR dessa copia ja atualizada
3. empacota o manifesto como um .thor de pasta (indice seguinte)
4. poe o hash novo na lista do SERVIDOR, mantendo o antigo
5. SO ENTAO publica os dois .thor
```

**O servidor vem antes do patch.** Se você publicar primeiro, quem atualizar na frente terá um
manifesto que o servidor ainda não conhece — e é recusado. **E o hash antigo fica na lista**
durante a transição, senão quem ainda *não* atualizou é que é recusado. Com os dois na lista,
as duas versões convivem.

### Passo a passo

```powershell
# 2. gerar o manifesto a partir da copia JA atualizada (nao do cliente de dev)
cd "D:\DEV Ragnarok\ragnalink-patcher"
cargo run --locked -p rse-manifest -- "<pasta da copia atualizada>"

# o hash que vai para a lista e o SHA-256 do arquivo gerado:
Get-FileHash "<pasta da copia atualizada>\rse_manifest.txt" -Algorithm SHA256
```

```yaml
# 3. patch.yml do manifesto — arquivo SOLTO, entao merging desligado
use_grf_merging: false
include_checksums: true
entries:
  - relative_path: rse_manifest.txt
```

```bash
# 4. no VPS, /opt/ragnalink/.env — hash NOVO primeiro, ANTIGO depois, sem espaco
RSE_MANIFESTOS_ACEITOS=<hash-novo>,<hash-antigo>

docker compose up -d ragnalink
docker logs ragnalink 2>&1 | grep -i manifesto     # espera "2 manifesto(s) aceito(s)"
```

Depois que todo mundo atualizou (dias, não horas), tire o hash antigo da lista.

### Se esquecer, como é o sintoma

O jogador clica em JOGAR e recebe uma caixa dizendo *"Os arquivos do seu cliente estão
diferentes dos publicados pelo servidor"*. O jogo não abre. No servidor:

```bash
docker logs ragnalink 2>&1 | grep CLIENT_HASH_UNKNOWN
```

**Conserto:** acrescente o hash que estiver faltando na lista e suba o container. Para
descobrir qual é, deixe a lista vazia por um minuto e olhe o log — ele registra o
`client_hash` de toda emissão:

```bash
docker logs ragnalink 2>&1 | grep "ticket emitido"
```

### Duas coisas que ajudam

- **A saída do `rse-manifest` é determinística** (lista ordenada, sem data). Rodar duas vezes
  no mesmo cliente dá o arquivo byte a byte idêntico. Se o hash mudou sem você ter mexido em
  nada, **algum arquivo mudou de verdade** — vale investigar antes de publicar.
- **O manifesto não descreve a si mesmo**, então não há circularidade: dá para gerá-lo e
  empacotá-lo no mesmo ciclo.

## Passo 6 — Publicar

Duas coisas, nessa ordem — **arquivo primeiro, lista depois**. Se inverter, existe uma
janela de segundos em que o patcher lê a lista e tenta baixar um arquivo que ainda não
está lá.

```bash
# 1) manda o arquivo
scp ragnalink_007.thor phillipe@45.179.88.179:/opt/ragnalink/patch/data/

# 2) acrescenta a linha na lista
echo "7 ragnalink_007.thor" >> /opt/ragnalink/patch/plist.txt
```

Vale na hora. Sem push, sem deploy, sem reiniciar container.

## Passo 7 — Conferir

```bash
curl -s https://ragnalink.com.br/patch/plist.txt
curl -so /dev/null -w '%{http_code} %{size_download}\n' \
     https://ragnalink.com.br/patch/data/ragnalink_007.thor
```

O tamanho tem que bater com o do arquivo local. E atenção ao motivo de olhar o
**tamanho** e não só o código: o site transforma arquivo faltando em redirect para a
página de erro, que responde **200 com HTML**. Status 200 sozinho não prova nada.

Depois abra o patcher num cliente que ainda não atualizou e veja o patch entrar.

---

## Se errou um patch já publicado

Não apague, não renumere. Publica o **próximo** índice desfazendo:

- arquivo errado -> novo patch com a versão certa do mesmo caminho
- arquivo que não devia existir -> novo patch com `is_removed: true`

Quem já pegou o errado recebe a correção; quem ainda não pegou recebe os dois em
sequência e termina no mesmo lugar.

---

## Resumo de bolso

```
1. pasta com o que mudou
2. patch.yml (include_checksums: true)
3. mkpatch.exe patch.yml -p <pasta> -o ragnalink_00N.thor
4. testar por "Patch manual" numa cópia
5. RagnaShield (se mexeu em GRF ou .exe):
     rse-manifest na cópia atualizada  ->  .thor do rse_manifest.txt (índice N+1)
     hash novo + antigo no RSE_MANIFESTOS_ACEITOS  ->  subir o container
     ^^ o SERVIDOR vem ANTES de publicar. Pular isto tranca jogador.
6. scp dos .thor  ->  depois  echo "N ..." >> plist.txt
7. conferir tamanho pelo curl
```
