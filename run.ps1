$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
    .\.venv\Scripts\python -m pip install -r requirements.txt
}
Write-Host "Starting Stegano. Admin password defaults to 1234 unless ADMIN_PASSWORD is set."
.\.venv\Scripts\python -m uvicorn steg.web:app --reload
