# Remove the machine-wide Prismor install. Runs as SYSTEM or an elevated admin.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    & "$env:WINDIR\sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}
$root = Join-Path $env:ProgramFiles "Prismor"
$py = Join-Path $root "current\python.exe"
if (Test-Path $py) {
    & $py -m prismor.runtime.immunity_cli uninstall-hooks --scope system --agent all *> $null
}
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$kept = ($machinePath -split ";") | Where-Object { $_ -and $_ -ne "$root\bin" }
[Environment]::SetEnvironmentVariable("Path", ($kept -join ";"), "Machine")
if (Test-Path "$root\current") { cmd /c rmdir "$root\current" | Out-Null }
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $env:ProgramData "Prismor") -ErrorAction SilentlyContinue
Write-Output "Prismor removed."
exit 0
