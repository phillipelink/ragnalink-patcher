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

## Passo 5 — Publicar

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

## Passo 6 — Conferir

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
5. scp do .thor  ->  depois  echo "N ragnalink_00N.thor" >> plist.txt
6. conferir tamanho pelo curl
```
