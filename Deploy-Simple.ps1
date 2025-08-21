# ============================================================================
# Vision One Endpoint Security Agent Simple Deployment Script
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
    
    [string]$SourceDir = ".\installer"
)

function Test-InstallerAvailability {
    param([string]$InstallerDir)
    
    Write-Host "Validating installer availability..." -ForegroundColor Yellow
    
    # Check if installer directory exists
    if (-not (Test-Path $InstallerDir)) {
        Write-Host ""
        Write-Host "❌ INSTALLER DIRECTORY NOT FOUND" -ForegroundColor Red
        Write-Host "Directory: $InstallerDir" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "SETUP REQUIRED:" -ForegroundColor Cyan
        Write-Host "1. Create the installer directory: $InstallerDir" -ForegroundColor White
        Write-Host "2. Download your unique Vision One Endpoint Security Agent installer ZIP from Trend Micro Vision One portal" -ForegroundColor White
        Write-Host "3. Place the ZIP file in the installer directory" -ForegroundColor White
        Write-Host "4. Do NOT extract the ZIP file - scripts handle extraction automatically" -ForegroundColor White
        return $false
    }
    
    # Check for ZIP files
    $zipFiles = Get-ChildItem -Path $InstallerDir -Filter "*.zip" -ErrorAction SilentlyContinue
    if ($zipFiles.Count -eq 0) {
        Write-Host ""
        Write-Host "❌ NO INSTALLER ZIP FILES FOUND" -ForegroundColor Red
        Write-Host "Directory checked: $InstallerDir" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "REQUIRED STEPS:" -ForegroundColor Cyan
        Write-Host "1. Log into your Trend Micro Vision One portal" -ForegroundColor White
        Write-Host "2. Navigate to Endpoint Security > Agent Management" -ForegroundColor White
        Write-Host "3. Download your organization's unique installer package" -ForegroundColor White
        Write-Host "4. Place the downloaded ZIP file in: $InstallerDir" -ForegroundColor White
        Write-Host "5. Do NOT extract the ZIP - leave it as a ZIP file" -ForegroundColor White
        Write-Host ""
        Write-Host "NOTE: Each organization has a unique installer that cannot be shared." -ForegroundColor Yellow
        return $false
    }
    
    # Validate ZIP files
    $validZips = 0
    foreach ($zipFile in $zipFiles) {
        try {
            # Test if ZIP file is readable
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
            $zip.Dispose()
            $validZips++
            Write-Host "✅ Valid installer found: $($zipFile.Name) ($($zipFile.Length) bytes)" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Invalid ZIP file: $($zipFile.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    if ($validZips -eq 0) {
        Write-Host ""
        Write-Host "❌ NO VALID ZIP FILES FOUND" -ForegroundColor Red
        Write-Host "Found ZIP files but they appear to be corrupted:" -ForegroundColor Yellow
        $zipFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Yellow }
        Write-Host ""
        Write-Host "SOLUTIONS:" -ForegroundColor Cyan
        Write-Host "1. Re-download the installer from Trend Micro Vision One portal" -ForegroundColor White
        Write-Host "2. Ensure the download completed successfully" -ForegroundColor White
        Write-Host "3. Check that the file is not corrupted (compare file size)" -ForegroundColor White
        return $false
    }
    
    Write-Host "✅ Installer validation completed - found $validZips valid installer(s)" -ForegroundColor Green
    return $true
}

Write-Host "=== Vision One Endpoint Security Agent Simple Deployment ===" -ForegroundColor Cyan
Write-Host "Target: $TargetIP" -ForegroundColor White
Write-Host "Source: $SourceDir" -ForegroundColor White
Write-Host ""

# Early validation - check for installer before doing anything else
if (-not (Test-InstallerAvailability $SourceDir)) {
    Write-Host ""
    Write-Host "❌ Deployment cannot proceed without a valid installer." -ForegroundColor Red
    Write-Host "Please follow the setup instructions above and try again." -ForegroundColor Yellow
    exit 1
}
# Prompt for credentials
Write-Host "Please enter credentials for an account with administrator permissions on target machines" -ForegroundColor Yellow
Write-Host "Format: DOMAIN\username (e.g., CONTOSO\admin)" -ForegroundColor Gray
Write-Host ""

$cred = Get-Credential -Message "Enter deployment credentials (DOMAIN\username)"

if (-not $cred) {
    Write-Host "Deployment cancelled - credentials are required" -ForegroundColor Red
    exit 1
}

# Validate credential format and prompt for domain if needed
if ($cred.UserName -notmatch "\\") {
    Write-Warning "Username should be in DOMAIN\username format"
    Write-Host ""
    
    # Prompt for domain
    $domainName = ""
    while ([string]::IsNullOrWhiteSpace($domainName)) {
        $domainName = Read-Host "Enter domain name (e.g., CONTOSO, your.domain.com)"
        if ([string]::IsNullOrWhiteSpace($domainName)) {
            Write-Host "Domain name is required" -ForegroundColor Red
        }
    }
    
    # Create new credential with proper domain format
    $newUsername = "$domainName\$($cred.UserName)"
    $cred = New-Object System.Management.Automation.PSCredential($newUsername, $cred.Password)
}

Write-Host "✓ Credentials loaded for user: $($cred.UserName)" -ForegroundColor Green
Write-Host ""

try {
    # Step 0: Check for existing Trend Micro products
    Write-Host "Step 0: Checking for existing Trend Micro products..." -ForegroundColor Yellow
    
    # Check for existing Trend Micro software
    $existingSoftware = Get-WmiObject -Class Win32_Product -ComputerName $TargetIP -Credential $cred -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*Vision One*"
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
    if (Test-Path "\\$TargetIP\C$\temp\Trend Micro\V1ES") {
        Remove-Item "\\$TargetIP\C$\temp\Trend Micro\V1ES\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Create directory
    New-Item -ItemType Directory -Path "\\$TargetIP\C$\temp\Trend Micro\V1ES" -Force | Out-Null
    
    # Find and copy installer zip file with smart selection
    $zipFiles = Get-ChildItem -Path $SourceDir -Filter "*.zip" | Sort-Object LastWriteTime -Descending
    if ($zipFiles.Count -eq 0) {
        throw "No zip files found in $SourceDir. Please place your Vision One Endpoint Security Agent installer zip in the installer directory."
    }
    
    if ($zipFiles.Count -gt 1) {
        Write-Host "Multiple zip files found:" -ForegroundColor Yellow
        $zipFiles | ForEach-Object { Write-Host "  - $($_.Name) ($(Get-Date $_.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow }
        
        # Smart selection: prefer files without (1), (2), etc. suffixes
        $preferredFile = $zipFiles | Where-Object { $_.Name -notmatch '\(\d+\)\.zip$' } | Select-Object -First 1
        if ($preferredFile) {
            $zipFile = $preferredFile
            Write-Host "Selected: $($zipFile.Name) (original filename)" -ForegroundColor Green
        } else {
            # If all files have duplicate suffixes, use the most recent one
            $zipFile = $zipFiles[0]
            Write-Host "Selected: $($zipFile.Name) (most recent)" -ForegroundColor Green
        }
    } else {
        $zipFile = $zipFiles[0]
    }
    
    Write-Host "Found installer zip: $($zipFile.Name) ($($zipFile.Length) bytes)" -ForegroundColor White
    
    # Copy zip file to target
    Copy-Item -Path $zipFile.FullName -Destination "\\$TargetIP\C$\temp\Trend Micro\V1ES\$($zipFile.Name)" -Force
    Write-Host "Copied zip file to target machine" -ForegroundColor Green
    
    # Extract zip file on target machine
    Write-Host "Extracting installer files on target machine..." -ForegroundColor Yellow
    
    # Use credentials from earlier prompt
    
    $extractionResult = Invoke-Command -ComputerName $TargetIP -Credential $cred -ScriptBlock {
        param($ZipPath, $ExtractPath)
        
        try {
            # Extract using .NET System.IO.Compression
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractPath)
            
            # Count extracted files
            $extractedFiles = Get-ChildItem -Path $ExtractPath -Recurse -File
            
            # Find main executable
            $mainExe = Get-ChildItem -Path $ExtractPath -Name "*.exe" -Recurse | Select-Object -First 1
            
            return @{
                Success = $true
                FileCount = $extractedFiles.Count
                MainExecutable = $mainExe
            }
        } catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    } -ArgumentList "C:\temp\Trend Micro\V1ES\$($zipFile.Name)", "C:\temp\Trend Micro\V1ES"
    
    if ($extractionResult.Success) {
        Write-Host "✅ Extracted $($extractionResult.FileCount) files" -ForegroundColor Green
        
        # Update installer command to use found executable
        if ($extractionResult.MainExecutable) {
            $installCommand = "C:\temp\Trend Micro\V1ES\$($extractionResult.MainExecutable) /S /v`"/quiet /norestart`""
            Write-Host "Main executable: $($extractionResult.MainExecutable)" -ForegroundColor Green
        } else {
            throw "No executable found in extracted files"
        }
        
        # Clean up zip file
        Remove-Item "\\$TargetIP\C$\temp\Trend Micro\V1ES\$($zipFile.Name)" -Force -ErrorAction SilentlyContinue
    } else {
        throw "Extraction failed: $($extractionResult.Error)"
    }
    
    # Step 2: Install
    Write-Host "Step 2: Starting installation..." -ForegroundColor Yellow
    
    # Execute installation using the dynamically found executable
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
    
    # Step 4: Check for Vision One processes
    Write-Host "Step 4: Checking for Vision One services..." -ForegroundColor Yellow
    
    $visionProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred | Where-Object { 
        $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
    }
    
    if ($visionProcesses) {
        Write-Host "✅ SUCCESS: Vision One processes detected!" -ForegroundColor Green
        Write-Host "Detected processes:" -ForegroundColor White
        $visionProcesses | Select-Object Name, ProcessId | Format-Table -AutoSize
    } else {
        Write-Host "⚠️  No Vision One processes detected yet" -ForegroundColor Yellow
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