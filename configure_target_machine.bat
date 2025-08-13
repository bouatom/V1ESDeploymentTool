@echo off
REM ============================================================================
REM VisionOne SEP Target Machine Configuration Script
REM ============================================================================
REM
REM PURPOSE: Configure target machines to accept remote VisionOne SEP deployment
REM ACTIONS: 
REM   - Enables WinRM service and configures authentication
REM   - Starts WMI service and sets to automatic startup
REM   - Enables PowerShell remoting
REM   - Configures DCOM settings for WMI access
REM   - Disables UAC remote restrictions
REM
REM USAGE: Copy this file to target machine and run as Administrator
REM
REM REQUIREMENTS: Must be run as Administrator on the TARGET machine
REM
REM ============================================================================

echo Configuring target machine for VisionOne SEP deployment...
echo.

echo === Enabling WinRM ===
winrm quickconfig
if %errorlevel% neq 0 (
    echo Failed to configure WinRM
    pause
    exit /b 1
)

echo === Configuring WinRM Settings ===
winrm set winrm/config/service @{AllowUnencrypted="true"}
winrm set winrm/config/service/auth @{Basic="true";Kerberos="true";Negotiate="true"}
winrm set winrm/config/winrs @{MaxMemoryPerShellMB="2048"}

echo === Configuring WMI Services ===
net start winmgmt
sc config winmgmt start= auto

echo === Configuring DCOM for WMI ===
REM Allow DCOM authentication for WMI
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{76A64158-CB41-11D1-8B02-00600806D9B6}" /v "AuthenticationLevel" /t REG_DWORD /d 1 /f

echo === Disabling UAC Remote Restrictions ===
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f

echo === Enabling PowerShell Remoting ===
powershell -Command "Enable-PSRemoting -Force -SkipNetworkProfileCheck"
powershell -Command "Set-ExecutionPolicy RemoteSigned -Force"

echo === Testing Configuration ===
winrm id
if %errorlevel% equ 0 (
    echo ✅ WinRM is working
) else (
    echo ❌ WinRM test failed
)

echo.
echo Configuration complete!
echo You can now run the deployment tool from your deployment machine.
pause
