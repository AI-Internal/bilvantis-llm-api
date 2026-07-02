# BilvantisLLM-API installer (Windows) — clones the repo and starts it with Docker Compose.
$ErrorActionPreference = 'Stop'

$RepoUrl   = if ($env:REPO_URL)   { $env:REPO_URL }   else { 'https://github.com/AI-Internal/bilvantis-llm-api.git' }
$TargetDir = if ($env:TARGET_DIR) { $env:TARGET_DIR } else { 'bilvantisllmapi' }

if (-not (Get-Command git -ErrorAction SilentlyContinue))    { throw 'git is required' }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'docker is required' }

if (-not (Test-Path (Join-Path $TargetDir '.git'))) {
  git clone $RepoUrl $TargetDir
}
Set-Location $TargetDir

if (-not (Test-Path '.env')) {
  $key = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Minimum 0 -Maximum 256) })
  "ENCRYPTION_KEY=$key`nPORT=3001" | Out-File -FilePath '.env' -Encoding ascii
  Write-Host 'Wrote .env with a fresh ENCRYPTION_KEY.'
}

docker compose up -d
Write-Host 'BilvantisLLM-API is starting. Open the dashboard at http://localhost:3001'
