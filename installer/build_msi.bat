@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: Build script for the PDA Uptime Agent MSI installer.
::
:: Prerequisites (install once):
::   pip install pyinstaller pywin32 requests
::   dotnet tool install --global wix
::   wix extension add WixToolset.Util.wixext
::
:: Usage:
::   cd installer
::   build_msi.bat
::
:: Output: PDAUptimeAgent.msi
:: =============================================================================

echo.
echo ===================================================
echo  PDA Uptime Agent — MSI Build Pipeline
echo ===================================================
echo.

:: --- Step 1: Freeze with PyInstaller -----------------------------------------
echo [1/3] Freezing agent into standalone .exe with PyInstaller...
pyinstaller --clean --noconfirm PDAUptimeAgent.spec

if not exist "dist\PDAUptimeAgent.exe" (
    echo.
    echo ERROR: PyInstaller did not produce dist\PDAUptimeAgent.exe
    echo Check the output above for errors.
    exit /b 1
)
echo       Done — dist\PDAUptimeAgent.exe created.
echo.

:: --- Step 2: Build MSI with WiX v4 ------------------------------------------
echo [2/3] Building MSI with WiX...
wix build pda_agent.wxs -o PDAUptimeAgent.msi -ext WixToolset.Util.wixext

if not exist "PDAUptimeAgent.msi" (
    echo.
    echo ERROR: WiX did not produce PDAUptimeAgent.msi
    echo Check the output above for errors.
    exit /b 1
)
echo       Done — PDAUptimeAgent.msi created.
echo.

:: --- Step 3: Summary ---------------------------------------------------------
echo ===================================================
echo  Build complete!
echo.
echo  Installer: %CD%\PDAUptimeAgent.msi
echo.
echo  Deploy with:
echo    msiexec /i PDAUptimeAgent.msi /qn
echo.
echo  Or with custom server URL:
echo    msiexec /i PDAUptimeAgent.msi /qn PDA_SERVER_URL=http://your-server:5000/heartbeat PDA_AGENT_TOKEN=your-token
echo ===================================================
echo.

endlocal
