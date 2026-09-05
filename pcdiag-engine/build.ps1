# Build do PC Diagnostic Engine.
#
# Nao precisa de .NET SDK, MSBuild nem Visual Studio: usa o compilador C# que
# ja vem no Windows (parte do .NET Framework 4.x). Isso significa que qualquer
# maquina Windows 10/11 consegue compilar esta ferramenta sem instalar nada.
[CmdletBinding()]
param(
    [switch]$Tests,        # compila e roda tambem a suite de testes
    [switch]$Clean,
    [string]$SignCertThumbprint,  # assinatura Authenticode opcional
    [string]$SignTimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path $root 'src'
$testDir = Join-Path $root 'tests'
$binDir = Join-Path $root 'bin'

$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) {
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path $csc)) {
    throw "Compilador C# nao encontrado. Este projeto exige .NET Framework 4.x, que faz parte do Windows 10/11."
}

if ($Clean -and (Test-Path $binDir)) {
    Remove-Item $binDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$references = @(
    'System.dll'
    'System.Core.dll'
    'System.Management.dll'
    'System.Xml.dll'
    'System.ServiceProcess.dll'
) | ForEach-Object { "/reference:$_" }

# --- executavel principal ---
$sources = Get-ChildItem $srcDir -Recurse -Filter *.cs | ForEach-Object { $_.FullName }
Write-Host "Compilando PcDiag.exe ($($sources.Count) arquivos)..." -ForegroundColor Cyan

$exePath = Join-Path $binDir 'PcDiag.exe'
$manifest = Join-Path $srcDir 'PcDiag.manifest'
if (-not (Test-Path $manifest)) { throw "Manifesto nao encontrado: $manifest" }

# O manifesto e obrigatorio: sem ele o Windows reporta a versao errada do
# sistema (version lie) e a deteccao de compatibilidade falha.
& $csc /nologo /target:exe /platform:anycpu /optimize+ /warn:4 /win32manifest:$manifest /out:$exePath $references $sources
if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar PcDiag.exe (codigo $LASTEXITCODE)." }
Write-Host "  -> $exePath" -ForegroundColor Green

# Defesa em profundidade alem do TryUnblock em SensorSource.cs:
# loadFromRemoteSources garante que o Assembly.LoadFrom das DLLs de sensor em
# bin\lib funcione mesmo quando o desbloqueio em codigo falhar por algum
# motivo (permissao, volume exotico). Se voce redistribuir o binario
# compilado, recomendamos assinar com um certificado Authenticode proprio
# (-SignCertThumbprint) para que o Windows/SmartScreen confie na origem.
$configPath = "$exePath.config"
@'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <loadFromRemoteSources enabled="true"/>
  </runtime>
</configuration>
'@ | Set-Content -Path $configPath -Encoding UTF8
Write-Host "  -> $configPath" -ForegroundColor Green

# --- assinatura Authenticode (opcional) ---
# Este passo so roda quando um certificado e informado (-SignCertThumbprint
# ou a variavel de ambiente PCDIAG_SIGN_CERT_THUMBPRINT) E signtool.exe esta
# disponivel; do contrario apenas avisa e segue sem assinar, para nao
# quebrar o build de quem nao tem certificado OV/EV instalado.
$certThumbprint = $SignCertThumbprint
if ([string]::IsNullOrEmpty($certThumbprint)) { $certThumbprint = $env:PCDIAG_SIGN_CERT_THUMBPRINT }
if (-not [string]::IsNullOrEmpty($certThumbprint)) {
    $signtoolCmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($signtoolCmd) {
        Write-Host "Assinando $exePath (Authenticode sha256, thumbprint $certThumbprint)..." -ForegroundColor Cyan
        & $signtoolCmd.Source sign /fd sha256 /tr $SignTimestampUrl /td sha256 /sha1 $certThumbprint $exePath
        if ($LASTEXITCODE -ne 0) { throw "Falha ao assinar PcDiag.exe (codigo $LASTEXITCODE)." }
        Write-Host "  -> PcDiag.exe assinado" -ForegroundColor Green
    } else {
        Write-Host "  aviso: signtool.exe nao encontrado no PATH; PcDiag.exe NAO foi assinado." -ForegroundColor Yellow
    }
} else {
    Write-Host "  aviso: nenhum certificado configurado (-SignCertThumbprint / PCDIAG_SIGN_CERT_THUMBPRINT); PcDiag.exe distribuido sem assinatura Authenticode." -ForegroundColor Yellow
}

# --- suite de testes ---
if ($Tests) {
    # Os testes referenciam o codigo de producao compilando os mesmos fontes,
    # menos o Entry.cs (que tem outro Main): assim ParseArguments,
    # StressModuleBudgetMs, ResolveOutputDirectory e WriteOutputs continuam
    # cobertos, e so o Main minimo fica de fora.
    $testSources = @()
    $testSources += (Get-ChildItem $srcDir -Recurse -Filter *.cs |
        Where-Object { $_.Name -ne 'Entry.cs' } | ForEach-Object { $_.FullName })
    $testSources += (Get-ChildItem $testDir -Recurse -Filter *.cs | ForEach-Object { $_.FullName })

    Write-Host "Compilando PcDiag.Tests.exe ($($testSources.Count) arquivos)..." -ForegroundColor Cyan
    $testExe = Join-Path $binDir 'PcDiag.Tests.exe'
    # Mesmo conjunto de flags do executavel de producao (/optimize+ e
    # /win32manifest inclusive), para que a suite valide o MESMO binario que
    # sera distribuido, nao uma build IL diferente.
    & $csc /nologo /target:exe /platform:anycpu /optimize+ /warn:4 /win32manifest:$manifest /out:$testExe $references $testSources
    if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar a suite de testes (codigo $LASTEXITCODE)." }
    Write-Host "  -> $testExe" -ForegroundColor Green

    Write-Host "Executando a suite de testes..." -ForegroundColor Cyan
    & $testExe
    if ($LASTEXITCODE -ne 0) {
        throw "Suite de testes falhou (codigo de saida $LASTEXITCODE)."
    }
    Write-Host "  -> suite de testes passou" -ForegroundColor Green
}

# --- bibliotecas de sensores (opcional) ---
# A pasta lib/ e opcional: sem ela a ferramenta roda normalmente e reporta
# "sensores indisponiveis" (temperatura, RPM de cooler etc.) em vez de
# falhar. Para habilitar a leitura de sensores, baixe o LibreHardwareMonitorLib
# (https://github.com/LibreHardwareMonitor/LibreHardwareMonitor) e coloque os
# .dll numa pasta "lib" na raiz deste projeto antes de rodar o build.
$libSource = Join-Path $root 'lib'
$libTarget = Join-Path $binDir 'lib'
if (Test-Path $libSource) {
    if (Test-Path $libTarget) { Remove-Item $libTarget -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $libTarget | Out-Null
    Copy-Item (Join-Path $libSource '*.dll') $libTarget -Force
    Write-Host "  -> bibliotecas de sensores copiadas para bin\lib" -ForegroundColor Green
} else {
    Write-Host "  aviso: pasta lib/ de sensores nao encontrada; a temperatura de hardware ficara indisponivel." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Build concluido." -ForegroundColor Green
