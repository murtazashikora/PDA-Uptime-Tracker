<#
.SYNOPSIS
    Downloads and installs the PDA Uptime Agent on a SERVER.
.DESCRIPTION
    Run from an elevated (Administrator) PowerShell prompt.
    Sets PDA_IS_SERVER=1 so the dashboard shows this node as a server.
.EXAMPLE
    .\Deploy-Server.ps1
#>

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$MsiUrl  = "https://github.com/murtazashikora/PDA-Uptime-Tracker/releases/download/v1.0.0/PDAUptimeAgent.msi"
$TempMsi = Join-Path $env:TEMP "PDAUptimeAgent.msi"

Write-Host "Downloading PDA Uptime Agent..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $MsiUrl -OutFile $TempMsi -UseBasicParsing

Write-Host "Installing on server..." -ForegroundColor Cyan
$proc = Start-Process msiexec -ArgumentList @(
    "/i", $TempMsi, "/qn",
    "PDA_SERVER_URL=http://182.156.143.144:5000/heartbeat",
    "PDA_AGENT_TOKEN=431f2a8fe5109152ab2c8a4c6d75473955d26c6a41fa4ac2",
    "PDA_IS_SERVER=1"
) -Wait -PassThru

Remove-Item $TempMsi -Force -ErrorAction SilentlyContinue

if ($proc.ExitCode -ne 0) {
    Write-Error "msiexec exited with code $($proc.ExitCode)"
    exit $proc.ExitCode
}

$svc = Get-Service -Name "PDAUptimeAgent" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "PDA Uptime Agent installed and running (server)." -ForegroundColor Green
} else {
    Write-Warning "Service installed but not running. Check Event Viewer."
}
