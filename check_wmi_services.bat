@echo off
REM Check WMI Services on Target Machine
REM Run this ON the target machine (10.0.5.127)

echo 🔍 Checking WMI Services...
echo.

echo === Windows Management Instrumentation ===
sc query winmgmt
echo.

echo === Remote Procedure Call (RPC) ===
sc query RpcSs
echo.

echo === RPC Endpoint Mapper ===
sc query RpcEptMapper
echo.

echo === DCOM Server Process Launcher ===
sc query DcomLaunch
echo.

echo === Testing Local WMI ===
wmic computersystem get name,domain
echo.

echo === WMI Service Status ===
wmic service where "name='winmgmt'" get name,state,startmode
echo.

echo === Firewall Status ===
netsh advfirewall show allprofiles state
echo.

pause