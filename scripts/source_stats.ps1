param(
  [int]$MinimumMbtLines = 6000
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$excluded = @("[\\/]\.git[\\/]", "[\\/]_build[\\/]", "[\\/]target[\\/]", "[\\/]\.repos[\\/]", "[\\/]\.mooncakes[\\/]")

function Test-InScope([string]$path) {
  foreach ($fragment in $excluded) {
    if ($path -match $fragment) {
      return $false
    }
  }
  return $true
}

$files = Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Filter "*.mbt" |
  Where-Object { Test-InScope $_.FullName }

$rows = foreach ($file in $files) {
  $lines = (Get-Content -LiteralPath $file.FullName | Measure-Object -Line).Lines
  $relative = $file.FullName.Substring($repoRoot.Length + 1)
  [pscustomobject]@{
    File = $relative
    Lines = $lines
    Kind = if ($relative -match '(^|[\\/])cmd[\\/]') { "cli" } elseif ($relative -match '_test\.mbt$') { "test" } else { "implementation" }
  }
}

$implementation = ($rows | Where-Object Kind -eq "implementation" | Measure-Object Lines -Sum).Sum
$tests = ($rows | Where-Object Kind -eq "test" | Measure-Object Lines -Sum).Sum
$cli = ($rows | Where-Object Kind -eq "cli" | Measure-Object Lines -Sum).Sum
$total = ($rows | Measure-Object Lines -Sum).Sum

Write-Host "MoonBit executable source statistics"
Write-Host "==================================="
Write-Host ("MBT files:          {0}" -f $rows.Count)
Write-Host ("Implementation lines: {0}" -f $implementation)
Write-Host ("Test lines:           {0}" -f $tests)
Write-Host ("CLI lines:            {0}" -f $cli)
Write-Host ("Total .mbt lines:     {0}" -f $total)
Write-Host ""
$rows | Sort-Object File | Format-Table -AutoSize

if ($total -lt $MinimumMbtLines) {
  throw "Executable MoonBit source is $total lines; minimum is $MinimumMbtLines."
}
