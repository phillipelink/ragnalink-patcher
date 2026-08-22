# Arte do RagnaShield (Loader)

Arquivos de **origem**. Nada aqui é compilado — o que entra no binário são os
`.bin` em `src/`. Isto existe para que, daqui a seis meses, dê para reeditar a
arte sem redescobrir como ela foi feita.

| Arquivo | O que é |
|---|---|
| `escudo_pixelart_1254.png` | Arte original do escudo, em pixel art. Grade nativa de **33 × 42 blocos** (cada bloco ≈ 19,4 px no arquivo de 1254 px). Fundo branco, sem alfa. |
| `icone_32.png` | O ícone da bandeja já pronto: 32 × 32 RGBA, escudo em 28 × 32 centrado. É a versão legível do `src/icone_bgra.bin`. |

## Como o `icone_bgra.bin` é gerado

1. **Recorta** o escudo do PNG grande (caixa envolvente do que não é branco).
2. **Quantiza na grade nativa** (33 × 42): a cor de cada bloco é a *mediana* do
   miolo dele — mediana, e não média, para o antialias da borda não puxar a cor.
3. **Alfa por preenchimento a partir da borda**: só o branco *conectado à borda*
   vira transparente. Assim o branco de dentro do desenho (a espada) fica.
4. **Reduz para 28 × 32 com filtro de área (BOX)** e centraliza numa caixa 32 × 32.
5. **Premultiplica** o RGB pelo alfa e grava em ordem **BGRA**, que é o que o
   `CreateDIBSection` espera.

O formato do arquivo é simples: 32 × 32 × 4 = **4096 bytes**, sem cabeçalho,
de cima para baixo (o DIB é criado com altura negativa).

## Duas decisões que valem lembrar

**Por que pixel art e não a renderização do logo.** A versão anterior recortava
o escudo do logo grande. Aquele logo é uma renderização com sombra, brilho e
degradê fino: reduzido a 16 px vira borrão. Pior, o recorte pegava só a metade
de cima — na bandeja aparecia uma coroa sem base. Pixel art já é feita de
blocos chapados com contorno duro, então a redução mistura poucas cores.

**Por que 28 × 32 e não 32 × 32.** Esticar até a largura toda engorda o escudo
e come o aro prateado nas laterais. 28 mantém a proporção quase certa (a nativa
é 33/42 ≈ 0,79) e ainda preenche bem a caixa.

**Por que não existe um 16 × 16 dedicado.** Foi testado. Forçar contorno duro e
paleta reduzida a 16 px transforma o desenho em ruído xadrez — o antialias, que
a 32 px atrapalha, a 16 px é justamente o que segura a forma. Quem reduz melhor
aqui é o próprio Windows, partindo destes 32 px.
