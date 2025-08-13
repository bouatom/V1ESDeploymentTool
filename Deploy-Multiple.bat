@echo off
REM Deploy VisionOne SEP to multiple machines
REM Edit the IP addresses below for your target machines

echo Starting VisionOne SEP deployment to multiple machines...
echo.

powershell -ExecutionPolicy Bypass -File Deploy-Simple.ps1 -TargetIP 10.0.5.127
echo.
echo ========================================
echo.

REM Add more machines here:
REM powershell -ExecutionPolicy Bypass -File Deploy-Simple.ps1 -TargetIP 10.0.5.128
REM powershell -ExecutionPolicy Bypass -File Deploy-Simple.ps1 -TargetIP 10.0.5.129

echo All deployments completed!
pause