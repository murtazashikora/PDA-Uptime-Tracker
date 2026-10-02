<#
.SYNOPSIS
    Downloads and runs the PDA Uptime Agent uninstaller on a SERVER.
.DESCRIPTION
    Run from an elevated (Administrator) PowerShell prompt.
.EXAMPLE
    .\Uninstall-Server.ps1
#>

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$MsiUrl  = "https://github.com/murtazashikora/PDA-Uptime-Tracker/releases/download/v1.0.0/PDAUptimeAgent.msi"
$TempMsi = Join-Path $env:TEMP "PDAUptimeAgent.msi"

Write-Host "Downloading MSI for uninstall..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $MsiUrl -OutFile $TempMsi -UseBasicParsing

Write-Host "Uninstalling PDA Uptime Agent..." -ForegroundColor Cyan
$proc = Start-Process msiexec -ArgumentList @("/x", $TempMsi, "/qn") -Wait -PassThru

Remove-Item $TempMsi -Force -ErrorAction SilentlyContinue

if ($proc.ExitCode -ne 0) {
    Write-Error "msiexec exited with code $($proc.ExitCode)"
    exit $proc.ExitCode
}

$svc = Get-Service -Name "PDAUptimeAgent" -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "PDA Uptime Agent uninstalled successfully." -ForegroundColor Green
} else {
    Write-Warning "Service still exists. May need a reboot."
}
