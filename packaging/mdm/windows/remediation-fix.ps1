# Intune Remediations, fix half: re-apply the system install with the mode it
# was installed with. Enrollment is untouched (the device key is still there).
$root = Join-Path $env:ProgramFiles "Prismor"
$py = Join-Path $root "current\python.exe"
if (-not (Test-Path $py)) { Write-Output "Prismor runtime missing; redeploy the app"; exit 1 }
$mode = "enforce"
try { $mode = (Get-Content (Join-Path $env:ProgramData "Prismor\system.json") -Raw | ConvertFrom-Json).mode } catch {}
$env:PRISMOR_NO_UPDATE_CHECK = "1"
[string[]]$sel = if ($mode -eq "observe") { @() } else { @("--recommended") }
$null | & $py -m prismor.runtime.immunity_cli setup --system --mode $mode @sel
exit $LASTEXITCODE
