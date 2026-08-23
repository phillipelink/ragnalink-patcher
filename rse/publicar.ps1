<#
.SYNOPSIS
    Compila o Loader, a DLL (e opcionalmente o launcher) e publica no cliente.

    🚨 REGRA DE EDIÇÃO DESTE ARQUIVO: fora deste bloco de comentário, use
    SOMENTE ASCII — sem acento, sem travessão, sem aspas curvas.

    O arquivo é UTF-8 SEM BOM, e o PowerShell 5.1 lê arquivo sem BOM como
    cp1252. Um travessão "—" (E2 80 94 em UTF-8) vira três caracteres, e o
    terceiro deles é 0x94, que o PowerShell trata como ASPA DE FECHAMENTO.
    Dentro de um Write-Host, isso fecha a string no meio e o script inteiro
    para de compilar, com erro apontando para uma linha dezenas de linhas
    abaixo da culpada.

    Já aconteceu em 23/08/2026 — duas vezes. A segunda foi esta própria frase:
    ela citava o marcador de fim de bloco de comentário e, com isso, FECHAVA o
    bloco, jogando todo o texto de ajuda para dentro do código. Por isso aqui
    não se escreve esse marcador; descreve-se.

    Dentro deste bloco, acento é inofensivo — o bloco inteiro é ignorado.
    Lá fora, quebra tudo.

.DESCRIPTION
    Existe por causa de uma pegadinha que já mordeu uma vez, e que morde
    calado:

        cargo build ...        <- FALHA
        Copy-Item ... -Force   <- copia a versão ANTIGA assim mesmo

    O PowerShell não interrompe a sequência quando o `cargo` sai com erro. O
    resultado é um cliente rodando a DLL de ontem enquanto você testa o código
    de hoje — e a conclusão errada de que a detecção nova "não funciona".

    Este script confere `$LASTEXITCODE` a cada passo e só copia se tudo passou.
    No fim imprime a data de modificação dos arquivos publicados, para dar
    para ver com os próprios olhos que são novos.

.PARAMETER Cliente
    Pasta do cliente. Padrão: D:\DEV Ragnarok\ClienteRagnaLinK

.PARAMETER SoDll
    Compila e publica só a DLL (mais rápido quando se está mexendo em detecção).

.PARAMETER ComLauncher
    Compila TAMBÉM o `rpatchur` e o publica como `RagnaLinK.exe` na raiz do
    cliente.

    Não é o padrão porque o launcher muda pouco e o build dele é lento — mas
    quando ele muda, esquecer é caro. Em 23/08/2026 a impressão de máquina foi
    corrigida no `rpatchur/src/rse.rs`, só o Loader e a DLL foram republicados,
    e a espera por máquina não funcionava por um motivo invisível: o launcher
    em campo ainda mandava a impressão zerada.

    Por isso o script agora AVISA no fim quando o fonte do launcher é mais novo
    que o `RagnaLinK.exe` publicado, mesmo que você não passe este parâmetro.

.PARAMETER AtualizarLock
    Compila SEM `--locked` nesta execução, permitindo o Cargo.lock mudar.

    Use quando o build reclamar de "lock file needs to be updated" logo depois de
    um MEMBRO NOVO entrar no workspace — uma ferramenta de teste, por exemplo.
    Nesse caso a mudança de lock é legítima: o pacote novo precisa entrar nele.

    Não use como reflexo para qualquer erro de lock. O `--locked` existe porque
    re-resolver o grafo já trouxe crate exigindo rustc 1.85 num workspace preso
    em 1.68.2. Depois de rodar com este parâmetro, confira o diff do Cargo.lock:
    só deve aparecer o membro novo, e nenhuma versão de terceiro mudando.

.EXAMPLE
    .\rse\publicar.ps1
    .\rse\publicar.ps1 -SoDll
    .\rse\publicar.ps1 -ComLauncher            # depois de mexer em rpatchur/
    .\rse\publicar.ps1 -SoDll -AtualizarLock   # so depois de adicionar membro novo
#>
param(
    [string] $Cliente = "D:\DEV Ragnarok\ClienteRagnaLinK",
    [switch] $SoDll,
    [switch] $ComLauncher,
    [switch] $AtualizarLock
)

$ErrorActionPreference = "Stop"
$alvo = "i686-pc-windows-msvc"
$destino = Join-Path $Cliente "rse"
# O launcher publicado troca de nome: rpatchur.exe -> RagnaLinK.exe.
$launcherPublicado = Join-Path $Cliente "RagnaLinK.exe"

function Parar($mensagem) {
    Write-Host ""
    Write-Host "  X  $mensagem" -ForegroundColor Red
    Write-Host "     Nada foi copiado. O cliente continua com a versao anterior." -ForegroundColor Red
    Write-Host ""
    exit 1
}

if (-not (Test-Path $destino)) {
    Parar "nao achei a pasta $destino"
}

# --- compilar ---------------------------------------------------------------
#
# `--locked` de proposito: garante que ninguem re-resolveu o grafo de
# dependencias por acidente. Ja aconteceu de uma re-resolucao trazer um crate
# que exige rustc 1.85, e o workspace esta preso no 1.68.2 (ver rust-toolchain.toml).
#
# Se o --locked reclamar DEPOIS de voce adicionar um membro novo ao workspace,
# isso e esperado: rode uma vez sem ele, confira o diff do Cargo.lock (so deve
# aparecer o membro novo, nenhuma versao mudando), e volte a usar --locked.

$pacotes = @("rse-watchdog")
if (-not $SoDll)  { $pacotes = @("rse-loader", "rse-watchdog") }
if ($ComLauncher) { $pacotes += "rpatchur" }

if ($AtualizarLock) {
    Write-Host "  !  compilando SEM --locked; confira o diff do Cargo.lock depois." -ForegroundColor Yellow
}

foreach ($p in $pacotes) {
    Write-Host "compilando $p ..." -ForegroundColor Cyan

    # Duas linhas literais em vez de montar a lista de argumentos numa variavel.
    #
    # A versao anterior fazia `cargo build --release @trava ...` com
    # `$trava = @("--locked")`. O splatting do PowerShell para comando NATIVO nao
    # se comporta como para cmdlet: o cargo recebeu um `-` solto e recusou. Num
    # script de build, repetir uma linha custa menos que depurar expansao de
    # argumento no meio de uma sessao.
    if ($AtualizarLock) {
        cargo build --release --target $alvo -p $p
    } else {
        cargo build --release --locked --target $alvo -p $p
    }

    if ($LASTEXITCODE -ne 0) {
        # A mensagem do cargo para este caso e generica e nao diz o que fazer.
        # Como isto acontece toda vez que um membro novo entra no workspace,
        # vale gastar tres linhas apontando a saida em vez de deixar o proximo
        # eu adivinhando de novo.
        if (-not $AtualizarLock) {
            Write-Host ""
            Write-Host "     Se o erro acima for 'lock file needs to be updated' e voce" -ForegroundColor Yellow
            Write-Host "     acabou de adicionar um membro ao workspace, rode uma vez:" -ForegroundColor Yellow
            Write-Host "         .\rse\publicar.ps1 -SoDll -AtualizarLock" -ForegroundColor Yellow
        }
        Parar "a compilacao de $p falhou"
    }
}

# --- copiar -----------------------------------------------------------------

# Loader e DLL vao para <cliente>\rse\ ; o launcher vai para a RAIZ do cliente
# e com outro nome (RagnaLinK.exe). Por isso ele e copiado separado, abaixo.
$arquivos = @{ "rse_watchdog.dll" = "rse_watchdog.dll" }
if (-not $SoDll) { $arquivos["rse_loader.exe"] = "rse_loader.exe" }

foreach ($nome in $arquivos.Keys) {
    $origem = Join-Path "target\$alvo\release" $nome
    if (-not (Test-Path $origem)) { Parar "nao achei $origem" }

    try {
        Copy-Item $origem (Join-Path $destino $arquivos[$nome]) -Force
    } catch {
        # O caso comum aqui e o jogo estar aberto segurando a DLL.
        Parar "nao consegui copiar $nome ($($_.Exception.Message)). Feche o jogo e o launcher."
    }
}

if ($ComLauncher) {
    $origemLauncher = Join-Path "target\$alvo\release" "rpatchur.exe"
    if (-not (Test-Path $origemLauncher)) { Parar "nao achei $origemLauncher" }

    try {
        Copy-Item $origemLauncher $launcherPublicado -Force
    } catch {
        Parar "nao consegui copiar o launcher ($($_.Exception.Message)). Feche o RagnaLinK.exe."
    }
    Write-Host "  launcher publicado em $launcherPublicado" -ForegroundColor Green
}

# --- provar que sao novos ---------------------------------------------------

Write-Host ""
Write-Host "  publicado em $destino" -ForegroundColor Green
Get-ChildItem $destino -Filter "rse_*" |
    Select-Object Name, @{n = "Tamanho"; e = { "{0:N0} B" -f $_.Length } }, LastWriteTime |
    Format-Table -AutoSize
Write-Host "  Confira que o LastWriteTime e de agora." -ForegroundColor DarkGray
Write-Host ""

# --- o launcher publicado ficou para tras? ----------------------------------
#
# Este bloco existe por causa de 23/08/2026. A impressao de maquina foi
# corrigida em rpatchur/src/rse.rs, o Loader e a DLL foram republicados, o
# RSE_ESPERA_MINUTOS foi ligado -- e a espera nao valia para ninguem, porque o
# RagnaLinK.exe no cliente ainda era o de oito horas antes e continuava mandando
# a impressao zerada.
#
# O modo de falhar e o pior que existe: tudo "funciona", nada da erro, e o
# recurso simplesmente nao acontece. Um script de publicacao nao pode obrigar
# ninguem a recompilar, mas pode se recusar a deixar voce acreditar que esta
# atualizado.

if (Test-Path $launcherPublicado) {
    $fonteLauncher = Get-ChildItem "rpatchur\src" -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($fonteLauncher) {
        $publicado = Get-Item $launcherPublicado

        if ($fonteLauncher.LastWriteTime -gt $publicado.LastWriteTime) {
            Write-Host "  !  ATENCAO: o launcher publicado esta DESATUALIZADO." -ForegroundColor Yellow
            Write-Host "     $($fonteLauncher.Name) mudou em $($fonteLauncher.LastWriteTime)" -ForegroundColor Yellow
            Write-Host "     RagnaLinK.exe e de           $($publicado.LastWriteTime)" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "     O cliente esta rodando um launcher anterior a essa mudanca." -ForegroundColor Yellow
            Write-Host "     Para publicar tambem o launcher:" -ForegroundColor Yellow
            Write-Host "         .\rse\publicar.ps1 -ComLauncher" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}
