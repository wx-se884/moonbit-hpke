$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

function Invoke-Checked([string]$name, [scriptblock]$command) {
  Write-Host "==> $name"
  & $command
  if ($LASTEXITCODE -ne 0) {
    throw "$name failed with exit code $LASTEXITCODE"
  }
}

Invoke-Checked "Moon version" { moon --version }
Invoke-Checked "Format check" { moon fmt --check }
Invoke-Checked "Typecheck with denied warnings" { moon check --deny-warn }
Invoke-Checked "Regenerate public interfaces" { moon info }
Invoke-Checked "Native tests" { moon test --target native --deny-warn --no-parallelize }
Invoke-Checked "Executable source threshold" { & (Join-Path $PSScriptRoot "source_stats.ps1") }

Write-Host "Acceptance checks completed."
