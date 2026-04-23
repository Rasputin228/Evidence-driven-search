param(
    [switch]$InstallOptionalTools = $true,
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath = Join-Path $ProjectRoot ".venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
$DepsMarker = Join-Path $VenvPath ".deps-installed"

Set-Location $ProjectRoot

if (-not (Test-Path $VenvPath)) {
    python -m venv $VenvPath
}

if (-not (Test-Path $PythonExe)) {
    throw "Не найден Python внутри .venv"
}

if (-not (Test-Path $DepsMarker)) {
    & $PythonExe -m pip install --upgrade pip
    & $PythonExe -m pip install -r requirements.txt
    if ($InstallOptionalTools -and (Test-Path (Join-Path $ProjectRoot "requirements-optional.txt"))) {
        & $PythonExe -m pip install -r requirements-optional.txt
    }
    Set-Content -Path $DepsMarker -Value (Get-Date).ToString("s")
}

if (-not $env:OSINT_VERIFY_SSL) {
    $env:OSINT_VERIFY_SSL = "false"
}

Write-Host "OSINT Graph App стартует на http://127.0.0.1:$Port" -ForegroundColor Cyan
& $PythonExe -m uvicorn main:app --host 127.0.0.1 --port $Port
