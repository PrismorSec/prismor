# Wrap the built package folder into a .intunewin for an Intune Win32 app.
# Uses Microsoft's Win32 Content Prep Tool, pinned to v1.8.7.
#
#   powershell -File make_intunewin.ps1 -Package out\prismor-X-windows -Out out
#
# Intune app settings: install command
#   powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Token <fleet token>
# uninstall command
#   powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1
# install behavior: System. Detection: custom script, detect.ps1.
param([Parameter(Mandatory)][string]$Package, [string]$Out = ".")
$ErrorActionPreference = "Stop"
$tag = "v1.8.7"
$tool = Join-Path $env:TEMP "IntuneWinAppUtil-$tag.exe"
if (-not (Test-Path $tool)) {
    $url = "https://raw.githubusercontent.com/microsoft/Microsoft-Win32-Content-Prep-Tool/$tag/IntuneWinAppUtil.exe"
    Invoke-WebRequest -UseBasicParsing $url -OutFile $tool
}
$sig = Get-AuthenticodeSignature $tool
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
    Remove-Item $tool -Force
    throw "IntuneWinAppUtil.exe is not validly signed by Microsoft ($($sig.Status))"
}
New-Item -ItemType Directory -Force $Out | Out-Null
& $tool -c (Resolve-Path $Package) -s install.ps1 -o (Resolve-Path $Out) -q
if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil failed ($LASTEXITCODE)" }
$ver = (Get-Content (Join-Path $Package "VERSION") -Raw).Trim()
$dest = Join-Path $Out "prismor-$ver.intunewin"
Move-Item -Force (Join-Path $Out "install.intunewin") $dest
"built $dest ($([math]::Round((Get-Item $dest).Length / 1MB)) MB)"
