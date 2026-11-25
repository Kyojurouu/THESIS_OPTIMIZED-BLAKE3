# Builds optimized_blake3_hasher.exe (the engine used by the Autopsy module)
# from optimized_blake3.py with PyInstaller, then self-tests the result.
#   .\build_sidecar.ps1                      # uses "python" on PATH
#   .\build_sidecar.ps1 -Python C:\path\to\python.exe
param([string]$Python = "python")

$ErrorActionPreference = "Stop"

# Native tools (pip, PyInstaller) write progress and notices to stderr; under
# Windows PowerShell 5.1 that would abort the script, so success is judged by
# the exit code instead.
function Invoke-Native([scriptblock]$Command, [string]$Failure) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command 2>&1 | ForEach-Object { Write-Host $_ } }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw $Failure }
}

$moduleDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $moduleDirectory
try {
    Invoke-Native { & $Python -m pip install --disable-pip-version-check -r requirements.txt "pyinstaller==6.22.2" } `
        "Dependency installation failed."
    Invoke-Native { & $Python -m PyInstaller --noconfirm --clean --onefile `
        --name optimized_blake3_hasher --collect-all blake3 optimized_blake3.py } `
        "PyInstaller build failed."
    $builtExecutable = Join-Path $moduleDirectory "dist\optimized_blake3_hasher.exe"
    if (-not (Test-Path -LiteralPath $builtExecutable)) {
        throw "Expected executable was not produced: $builtExecutable"
    }
    Invoke-Native { & $builtExecutable --self-test } "The built engine failed its self-test."
    Write-Host "Built and self-tested: $builtExecutable"
    Write-Host "Copy it next to blake3_ingest_module.py (autopsy_plugin\BLAKE3_Autopsy_Module)."
}
finally { Pop-Location }
