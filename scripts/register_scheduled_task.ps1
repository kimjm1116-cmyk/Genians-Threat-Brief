# Windows 작업 스케줄러 등록 스크립트
# 관리자 PowerShell에서 실행:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\scripts\register_scheduled_task.ps1

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$RunScript = Join-Path $ProjectRoot "scripts\run_daily.ps1"

if (-not (Test-Path $PythonExe)) {
    Write-Host "가상환경이 없습니다. 먼저 setup.ps1을 실행하세요." -ForegroundColor Red
    exit 1
}

$TaskName = "ThreatIntelDailyReport"
$Trigger = New-ScheduledTaskTrigger -Daily -At "07:30"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$RunScript`""
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries

Register-ScheduledTask `
    -TaskName $TaskName `
    -Trigger $Trigger `
    -Action $Action `
    -Settings $Settings `
    -Description "국내외 위협현황 CTI 리포트를 Slack으로 매일 07:30에 전송" `
    -Force

Write-Host "작업 스케줄러 등록 완료: $TaskName (매일 07:30 KST)" -ForegroundColor Green
