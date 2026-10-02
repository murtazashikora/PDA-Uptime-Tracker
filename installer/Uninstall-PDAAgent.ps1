<#
.SYNOPSIS
    Silently uninstalls the PDA Uptime Agent.
.DESCRIPTION
    Run from an elevated (Administrator) PowerShell prompt.
.EXAMPLE
    .\Uninstall-PDAAgent.ps1
#>

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Find installed MSI by product name
$app = Get-WmiObject Win32_Product -Filter "Name='PDA Uptime Monitoring Agent'" -ErrorAction SilentlyContinue

if ($app) {
    Write-Host "Uninstalling PDA Uptime Agent..." -ForegroundColor Cyan
    $proc = Start-Process msiexec -ArgumentList @("/x", $app.IdentifyingNumber, "/qn") -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Error "msiexec exited with code $($proc.ExitCode)"
        exit $proc.ExitCode
    }
    Write-Host "PDA Uptime Agent uninstalled." -ForegroundColor Green
} else {
    Write-Warning "PDA Uptime Agent is not installed on this machine."
}
