#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs or uninstalls the PDA Uptime Monitoring Agent.
.DESCRIPTION
    Downloads PDAUptimeAgent.msi from GitHub and runs a silent install,
    or uninstalls the agent if -Uninstall is specified.
    Must be run as Administrator.
.PARAMETER ServerUrl
    The heartbeat endpoint URL. Default: https://uptimetracker.withbytecycle.com/heartbeat
.PARAMETER AgentToken
    Shared authentication token. Optional.
.PARAMETER IsServer
    Set to 1 if this machine is a server (not a workstation). Default: 0
.PARAMETER Uninstall
    Removes the agent, its service, and environment variables.
.EXAMPLE
    .\Install-PDAAgent.ps1
.EXAMPLE
    .\Install-PDAAgent.ps1 -AgentToken "my-secret-token" -IsServer 1
.EXAMPLE
    .\Install-PDAAgent.ps1 -Uninstall
#>

param(
    [string]$ServerUrl  = "https://uptimetracker.withbytecycle.com/heartbeat",
    [string]$AgentToken = "",
    [string]$IsServer   = "0",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$productName = "PDA Uptime Monitoring Agent"

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " PDA Uptime Agent — Remote Installer" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# UNINSTALL
# =============================================================================
if ($Uninstall) {
    Write-Host "[1/2] Finding installed agent..." -ForegroundColor Yellow

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $entry = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
             Where-Object { $_.DisplayName -like "*PDA*Uptime*" } |
             Select-Object -First 1

    if (-not $entry) {
        Write-Host "      Agent is not installed on this machine." -ForegroundColor Red
        exit 1
    }

    $productGuid = $entry.PSChildName
    Write-Host "      Found: $($entry.DisplayName) ($productGuid)" -ForegroundColor Green

    Write-Host "[2/2] Uninstalling..." -ForegroundColor Yellow
    $process = Start-Process msiexec.exe -ArgumentList "/x $productGuid /qn /norestart" -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Host "      msiexec exited with code $($process.ExitCode)" -ForegroundColor Red
        exit $process.ExitCode
    }

    Write-Host "      Uninstalled successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "Note: Logs at C:\ProgramData\PDAUptimeAgent\ were kept." -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# =============================================================================
# INSTALL
# =============================================================================
$downloadUrl = "https://github.com/murtazashikora/PDA-E-Services/raw/48159253eaeef0514832d0d9f9e1590b16b8436c/PDAUptimeAgent.msi"
$msiPath     = Join-Path $env:TEMP "PDAUptimeAgent.msi"

# --- Download ----------------------------------------------------------------
Write-Host "[1/3] Downloading installer..." -ForegroundColor Yellow
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $msiPath -UseBasicParsing
    $size = "{0:N2} MB" -f ((Get-Item $msiPath).Length / 1MB)
    Write-Host "      Downloaded to $msiPath ($size)" -ForegroundColor Green
}
catch {
    Write-Host "      Download failed: $_" -ForegroundColor Red
    exit 1
}

# --- Install -----------------------------------------------------------------
Write-Host "[2/3] Installing silently..." -ForegroundColor Yellow

$msiArgs = "/i `"$msiPath`" /qn /norestart PDA_SERVER_URL=$ServerUrl PDA_IS_SERVER=$IsServer"
if ($AgentToken) {
    $msiArgs += " PDA_AGENT_TOKEN=$AgentToken"
}

$process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Write-Host "      msiexec exited with code $($process.ExitCode)" -ForegroundColor Red
    exit $process.ExitCode
}
Write-Host "      Installed successfully." -ForegroundColor Green

# --- Verify ------------------------------------------------------------------
Write-Host "[3/3] Verifying service..." -ForegroundColor Yellow
$svc = Get-Service -Name "PDAUptimeAgent" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "      Service status: $($svc.Status)" -ForegroundColor Green
    if ($svc.Status -ne "Running") {
        Start-Service -Name "PDAUptimeAgent"
        Write-Host "      Service started." -ForegroundColor Green
    }
}
else {
    Write-Host "      WARNING: Service not found after install." -ForegroundColor Red
}

# --- Cleanup -----------------------------------------------------------------
Remove-Item $msiPath -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done. Logs: C:\ProgramData\PDAUptimeAgent\agent.log" -ForegroundColor Cyan
Write-Host ""
