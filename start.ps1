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

function Import-DotEnvFile {
    param(
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return
    }

    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            return
        }
        $parts = $line.Split("=", 2)
        if ($parts.Count -ne 2) {
            return
        }

        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (-not $key) {
            return
        }

        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        if (-not (Get-Item "Env:$key" -ErrorAction SilentlyContinue)) {
            Set-Item -Path "Env:$key" -Value $value
        }
    }
}

Import-DotEnvFile -Path (Join-Path $ProjectRoot ".env")

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

if (-not $env:OSINT_DB_PATH) {
    $env:OSINT_DB_PATH = Join-Path $ProjectRoot "osint_graph_app.db"
}

Write-Host "OSINT Graph App стартует на http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "SQLite: $env:OSINT_DB_PATH" -ForegroundColor DarkCyan
& $PythonExe -m uvicorn main:app --host 127.0.0.1 --port $Port
