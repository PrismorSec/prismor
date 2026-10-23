# Prismor machine-wide install for Intune (Win32 app), SCCM or a GPO startup
# script. Runs as SYSTEM (or an elevated admin). Idempotent: re-running it
# upgrades in place and re-applies the configuration.
#
#   powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Token <fleet token>
#
# -Mode enforce|observe   -Rules id1,id2 (default: the recommended set)
# -ApiBase https://...    -Label <device label> (default: computer name)
param(
    [string]$Token = "",
    [string]$Mode = "enforce",
    [string]$Rules = "",
    [string]$ApiBase = "",
    [string]$Label = ""
)
$ErrorActionPreference = "Stop"

# Intune can start 32-bit PowerShell; Program Files and the registry would
# then be redirected to their x86 views. Re-run under the 64-bit host.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $ps = "$env:WINDIR\sysnative\WindowsPowerShell\v1.0\powershell.exe"
    & $ps -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters
    exit $LASTEXITCODE
}

$ver = (Get-Content (Join-Path $PSScriptRoot "VERSION") -Raw).Trim()
$root = Join-Path $env:ProgramFiles "Prismor"
$rt = Join-Path $root "runtime\$ver"
$cur = Join-Path $root "current"
$logDir = Join-Path $env:ProgramData "PrismorInstall"
New-Item -ItemType Directory -Force $logDir | Out-Null
Start-Transcript -Append -Path (Join-Path $logDir "install.log") | Out-Null
try {
    Write-Output "=== install Prismor $ver"
    # Always mirror: robocopy skips identical files, and an interrupted copy or
    # a half-removed runtime (python.exe present, Lib gone) gets repaired.
    & robocopy (Join-Path $PSScriptRoot "runtime") $rt /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "copying the runtime failed (robocopy $LASTEXITCODE)" }
    # Hooks run "<root>\current\python.exe", so an upgrade only re-points this
    # junction; the hook configs stay valid throughout.
    if (Test-Path $cur) { cmd /c rmdir "$cur" | Out-Null }
    cmd /c mklink /J "$cur" "$rt" | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $root "bin") | Out-Null
    Copy-Item (Join-Path $PSScriptRoot "prismor.cmd") (Join-Path $root "bin\prismor.cmd") -Force
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (($machinePath -split ";") -notcontains "$root\bin") {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$root\bin", "Machine")
    }

    $py = Join-Path $cur "python.exe"
    $env:PRISMOR_NO_UPDATE_CHECK = "1"
    # [string[]], not a bare assignment: PowerShell unwraps a one-element array
    # to a string, and splatting a string passes it one character at a time.
    [string[]]$sel = @()
    if ($Mode -ne "observe") { $sel = if ($Rules) { @("--enforce-rules", $Rules) } else { @("--recommended") } }
    # `$null |`: no Prismor command may wait on stdin under an MDM agent.
    $null | & $py -m prismor.runtime.immunity_cli setup --system --mode $Mode @sel
    if ($LASTEXITCODE -ne 0) { throw "prismor setup --system failed ($LASTEXITCODE)" }

    if ($Token) {
        $null | & $py -m prismor.runtime.immunity_cli enroll-status *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Output "already enrolled; token not used"
        } else {
            if (-not $Label) { $Label = $env:COMPUTERNAME }
            $enroll = @("--label", $Label)
            if ($ApiBase) { $enroll += @("--api-base", $ApiBase) }
            # Through the environment, not argv: the fleet token is org-wide.
            $env:PRISMOR_ENROLL_TOKEN = $Token
            try { $null | & $py -m prismor.runtime.immunity_cli enroll @enroll }
            finally { Remove-Item Env:PRISMOR_ENROLL_TOKEN -ErrorAction SilentlyContinue }
            if ($LASTEXITCODE -ne 0) { throw "enrollment failed ($LASTEXITCODE)" }
            $null | & $py -m prismor.runtime.immunity_cli system-sync --quiet
        }
    }
    Set-Content -Path (Join-Path $root "VERSION") -Value $ver -Encoding ascii

    # Older runtimes: nothing points at them now. A file still held open by a
    # running hook is left for the next install to clear.
    Get-ChildItem (Join-Path $root "runtime") -Directory | Where-Object { $_.Name -ne $ver } |
        ForEach-Object { Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue }
    Write-Output "=== done"
    exit 0
} catch {
    Write-Output "ERROR: $_"
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
