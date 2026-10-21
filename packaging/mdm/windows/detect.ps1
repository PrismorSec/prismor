# Intune Win32 app detection rule: installed = this version's runtime is in
# place and the system install marker exists. Intune treats exit 0 plus any
# STDOUT as "detected".
$expected = "__VERSION__"
$root = Join-Path $env:ProgramFiles "Prismor"
$marker = Join-Path $env:ProgramData "Prismor\system.json"
$verFile = Join-Path $root "VERSION"
if ((Test-Path $marker) -and (Test-Path $verFile) -and ((Get-Content $verFile -Raw).Trim() -eq $expected)) {
    Write-Output "Prismor $expected installed"
    exit 0
}
exit 1
