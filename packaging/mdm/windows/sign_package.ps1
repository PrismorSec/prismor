# Authenticode-sign the package's PowerShell scripts, for fleets that run
# PowerShell under AllSigned or WDAC script enforcement.
#
#   powershell -File sign_package.ps1 -Package out\prismor-X-windows -PfxPath cert.pfx -PfxPassword <pw>
#
# -SignRuntime also signs python.exe/pythonw.exe and every .dll/.pyd in the
# bundled runtime (needs signtool, from the Windows SDK), for WDAC policies
# that only allow signed binaries.
param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$PfxPath,
    [string]$PfxPassword = "",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$SignRuntime,
    [switch]$AllowUntrustedRoot   # self-signed test certificates only
)
$ErrorActionPreference = "Stop"
$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $PfxPassword, $flags)
if (-not $cert.HasPrivateKey) { throw "the PFX has no private key" }
$n = 0
foreach ($f in Get-ChildItem $Package -Filter *.ps1) {
    $r = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -TimestampServer $TimestampServer -HashAlgorithm SHA256
    $okStatus = @("Valid") + $(if ($AllowUntrustedRoot) { @("UnknownError") } else { @() })
    if ($okStatus -notcontains [string]$r.Status) { throw "signing $($f.Name) failed: $($r.Status) $($r.StatusMessage)" }
    $n++
}
"signed $n scripts with $($cert.Subject)"
if ($SignRuntime) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\" } | Select-Object -Last 1
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)" }
    $bins = Get-ChildItem (Join-Path $Package "runtime") -Recurse -Include python.exe, pythonw.exe, *.dll, *.pyd
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr $TimestampServer /f $PfxPath /p $PfxPassword @($bins.FullName) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
    "signed $($bins.Count) runtime binaries"
}
