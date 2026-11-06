$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
    .\.venv\Scripts\python -m pip install -r requirements.txt
}
Write-Host "Starting Stegano. Set ADMIN_PASSWORD to configure admin login."
.\.venv\Scripts\python -m uvicorn steg.web:app --reload
