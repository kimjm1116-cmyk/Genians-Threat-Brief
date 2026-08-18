$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "국내외 위협현황 봇 환경 설정..." -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python이 설치되어 있지 않습니다." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

& .\.venv\Scripts\pip.exe install -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ".env 파일이 생성되었습니다. OPENAI_API_KEY와 SLACK_WEBHOOK_URL을 입력하세요." -ForegroundColor Yellow
}

Write-Host "설치 완료. 테스트: .\.venv\Scripts\python.exe -m src.main --test-slack" -ForegroundColor Green
