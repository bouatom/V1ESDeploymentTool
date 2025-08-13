# ============================================================================
# VisionOne SEP Simple Deployment Script
# ============================================================================
#
# PURPOSE: Quick single-host deployment with minimal configuration
# FEATURES:
#   - Single target deployment with basic checks
#   - Existing product detection with warnings
#   - Step-by-step progress display with colored output
#   - Installation monitoring and verification
#
# USAGE: .\Deploy-Simple.ps1 -TargetIP 10.0.5.127
#
# REQUIREMENTS:
#   - Edit default credentials below or use parameters
#   - PowerShell execution policy: RemoteSigned or Bypass
#   - Domain admin privileges for target machine
#   - Run configure_target_machine.bat on target first
#
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetIP,
    
    [string]$Username = "DOMAIN\username",      # Edit with your credentials
    [string]$Password = "your_password_here",   # Edit with your credentials
    [string]$SourceDir = ".\installer"
)

Write-Host "=== VisionOne SEP Simple Deployment ===" -ForegroundColor Cyan
Write-Host "Target: $TargetIP" -ForegroundColor White
Write-Host "Source: $SourceDir" -ForegroundColor White
Write-Host ""

try {
    # Step 0: Check for existing Trend Micro products
    Write-Host "Step 0: Checking for existing Trend Micro products..." -ForegroundColor Yellow
    
    $pass = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($Username, $pass)
    
    # Check for existing Trend Micro software
    $existingSoftware = Get-WmiObject -Class Win32_Product -ComputerName $TargetIP -Credential $cred -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*VisionOne*"
    }
    
    # Check for existing Trend Micro processes
    $existingProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
    }
    
    if ($existingSoftware -or $existingProcesses) {
        Write-Host "⚠️  Existing Trend Micro products detected:" -ForegroundColor Yellow
        if ($existingSoftware) {
            $existingSoftware | ForEach-Object { Write-Host "   Software: $($_.Name)" -ForegroundColor Yellow }
        }
        if ($existingProcesses) {
            $existingProcesses | ForEach-Object { Write-Host "   Process: $($_.Name)" -ForegroundColor Yellow }
        }
        Write-Host "Proceeding with installation (may cause conflicts)" -ForegroundColor Yellow
    } else {
        Write-Host "✅ No existing Trend Micro products found" -ForegroundColor Green
    }
    
    # Step 1: Copy Files
    Write-Host "Step 1: Copying installer files..." -ForegroundColor Yellow
    
    # Clean up any existing files
    if (Test-Path "\\$TargetIP\C$\temp\VisionOneSEP") {
        Remove-Item "\\$TargetIP\C$\temp\VisionOneSEP\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Create directory and copy files
    New-Item -ItemType Directory -Path "\\$TargetIP\C$\temp\VisionOneSEP" -Force | Out-Null
    Copy-Item -Path "$SourceDir\*" -Destination "\\$TargetIP\C$\temp\VisionOneSEP\" -Recurse -Force
    
    # Verify copy
    $mainExe = "\\$TargetIP\C$\temp\VisionOneSEP\EndpointBasecamp.exe"
    if (Test-Path $mainExe) {
        $fileSize = (Get-Item $mainExe).Length
        $fileCount = (Get-ChildItem "\\$TargetIP\C$\temp\VisionOneSEP" -Recurse -File).Count
        Write-Host "✅ Copied $fileCount files ($fileSize bytes for main exe)" -ForegroundColor Green
    } else {
        throw "Main executable not found after copy"
    }
    
    # Step 2: Install
    Write-Host "Step 2: Starting installation..." -ForegroundColor Yellow
    
    # Create credentials
    $pass = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($Username, $pass)
    
    # Execute installation
    $installCommand = "C:\temp\VisionOneSEP\EndpointBasecamp.exe /S /v`"/quiet /norestart`""
    $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $installCommand -ComputerName $TargetIP -Credential $cred
    
    if ($result.ReturnValue -eq 0) {
        Write-Host "✅ Installation started (ProcessId: $($result.ProcessId))" -ForegroundColor Green
    } else {
        throw "Installation failed to start (Return code: $($result.ReturnValue))"
    }
    
    # Step 3: Monitor
    Write-Host "Step 3: Monitoring installation..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le 6; $i++) {
        Start-Sleep -Seconds 30
        $processes = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
        
        if ($processes) {
            Write-Host "[$i/6] Installation running (PID: $($processes.ProcessId))" -ForegroundColor Yellow
        } else {
            Write-Host "[$i/6] Installation process completed" -ForegroundColor Green
            break
        }
    }
    
    # Step 4: Check for VisionOne processes
    Write-Host "Step 4: Checking for VisionOne services..." -ForegroundColor Yellow
    
    $visionProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred | Where-Object { 
        $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
    }
    
    if ($visionProcesses) {
        Write-Host "✅ SUCCESS: VisionOne processes detected!" -ForegroundColor Green
        Write-Host "Detected processes:" -ForegroundColor White
        $visionProcesses | Select-Object Name, ProcessId | Format-Table -AutoSize
    } else {
        Write-Host "⚠️  No VisionOne processes detected yet" -ForegroundColor Yellow
        Write-Host "Installation may still be in progress or may have failed" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "🎉 Deployment completed for $TargetIP" -ForegroundColor Green
    Write-Host "Check the target machine for final installation status" -ForegroundColor White
    
} catch {
    Write-Host ""
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}