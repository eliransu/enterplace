<#
.SYNOPSIS
Installs the Gantry device agent on Windows: the binary, the enrolment token, and a scheduled task that starts the
agent when a person signs in.

.DESCRIPTION
Run as administrator, or as SYSTEM from Intune (a Win32 app, see deploy/mdm/README.md). The agent runs as the
signed-in person, so it writes that person's own tool settings and nothing outside their profile.

  install.ps1 -ControlPlane https://gantry.example.com -Token gantry_dev_...
  install.ps1 -ControlPlane https://gantry.example.com -TokenFile .\device-token -Binary .\gantry.exe
  install.ps1 -Uninstall

The script is not signed. Sign it with your own code signing certificate (Set-AuthenticodeSignature) if your
execution policy asks for signed scripts, or run it with -ExecutionPolicy Bypass as Intune does.
#>
[CmdletBinding()]
param(
    # The gateway's address, https, as `gantry device --control-plane` takes it.
    [string]$ControlPlane,
    # The Gantry Enterprise binary for this machine (x86_64 or arm64).
    [string]$Binary = (Join-Path $PSScriptRoot 'gantry.exe'),
    # The enrolment token, or a file holding it. With neither, a token file already on the machine is kept.
    [string]$Token,
    [string]$TokenFile,
    # Seconds between the agent's checks.
    [int]$Interval = 300,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Gantry device agent'
$InstallDir = Join-Path $env:ProgramFiles 'Gantry'
$DataDir = Join-Path $env:ProgramData 'Gantry'
$TokenPath = Join-Path $DataDir 'device-token'
$Exe = Join-Path $InstallDir 'gantry.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as administrator: it writes to Program Files and registers a scheduled task.'
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Remove-Item -Recurse -Force $InstallDir, $DataDir -ErrorAction SilentlyContinue
    Write-Output 'Removed the Gantry device agent. Tool settings it wrote in each profile stay as they are.'
    exit 0
}

# The address goes into the task's command line, so only an address is taken.
if ($ControlPlane -notmatch '^https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._\-/]*)?$') {
    throw "-ControlPlane must be the gateway's https address, such as https://gantry.example.com. Got '$ControlPlane'."
}
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "No binary at $Binary. Pass -Binary with the path to gantry.exe."
}
if ($Interval -lt 30) {
    throw '-Interval is in seconds, 30 or more.'
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    # A running agent holds the binary open.
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
Copy-Item -LiteralPath $Binary -Destination $Exe -Force

if ($TokenFile) {
    $Token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
}
if ($Token) {
    if ($Token -notmatch '^gantry_dev_[0-9a-f]+$') {
        throw 'The enrolment token starts with gantry_dev_. Create one on the console''s Devices page.'
    }
    Set-Content -LiteralPath $TokenPath -Value $Token -NoNewline -Encoding ascii
} elseif (-not (Test-Path -LiteralPath $TokenPath)) {
    throw "No enrolment token: pass -Token or -TokenFile, or deliver it to $TokenPath first."
}
# The agent runs as the signed-in person, so people read the token; only administrators change it.
& icacls.exe $TokenPath /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' '*S-1-5-32-545:R' | Out-Null

# PowerShell starts the agent with no window. It runs until sign-out and checks every $Interval seconds.
$command = "& '$Exe' device --control-plane '$ControlPlane' --interval $Interval"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$command`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
# BUILTIN\Users: the task runs once for each person who signs in, as that person, without elevation.
$principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null

Write-Output "Installed $Exe and the task '$TaskName'. The agent starts at the next sign-in."
Write-Output "Try it now, as the person: `"$Exe`" device --control-plane $ControlPlane --dry-run"
