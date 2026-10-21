# Intune Remediations, detection half: exit 1 (needs remediation) when the
# system install has drifted: marker or a hook config missing, or a hook
# config no longer pointing at Prismor.
$sys = Join-Path $env:ProgramData "Prismor"
$checks = @(
    (Join-Path $sys "system.json"),
    (Join-Path $sys "hook-dispatch.py"),
    (Join-Path $env:ProgramFiles "ClaudeCode\managed-settings.d\50-prismor.json"),
    (Join-Path $env:ProgramData "OpenAI\Codex\requirements.toml")
)
foreach ($f in $checks) {
    if (-not (Test-Path $f)) { Write-Output "missing: $f"; exit 1 }
}
foreach ($f in $checks[2..3]) {
    if (-not (Select-String -Path $f -Pattern "hook-dispatch" -Quiet)) { Write-Output "no Prismor hook in $f"; exit 1 }
}
Write-Output "Prismor system install intact"
exit 0
