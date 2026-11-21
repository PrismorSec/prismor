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
$ndjson = Join-Path $env:ProgramData "Prismor\inventory\last.ndjson"
if (Test-Path $ndjson) {
    $ageHours = [math]::Round(((Get-Date) - (Get-Item $ndjson).LastWriteTime).TotalHours, 1)
    $counts = @{ none = 0; low = 0; medium = 0; high = 0; critical = 0 }
    Get-Content $ndjson | ForEach-Object {
        if (-not $_) { return }
        try { $row = $_ | ConvertFrom-Json } catch { return }
        $level = [string]$row.risk.level
        if ($counts.ContainsKey($level)) { $counts[$level]++ }
    }
    Write-Output ("inventory age_hours={0} none={1} low={2} medium={3} high={4} critical={5}" -f `
        $ageHours, $counts.none, $counts.low, $counts.medium, $counts.high, $counts.critical)
} else {
    Write-Output "inventory: no scan yet"
}
exit 0
