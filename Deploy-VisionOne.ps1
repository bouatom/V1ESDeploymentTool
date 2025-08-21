# ============================================================================
# Vision One Endpoint Security Agent Deployment Script - Primary Deployment Engine
# ============================================================================
# 
# PURPOSE: Full-featured deployment script for Trend Micro Vision One Endpoint Security Agent
# FEATURES: 
#   - Single host, multiple hosts, CIDR network scanning
#   - Parallel deployment with configurable concurrency
#   - Existing Trend Micro product detection and conflict handling
#   - Comprehensive pre-deployment checks (connectivity, WMI, SMB)
#   - Real-time monitoring and progress tracking
#   - Detailed audit logging and error reporting
#
# USAGE EXAMPLES:
#   .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'
#   .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128'
#   .\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24'
#   .\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt' -Parallel
#   .\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -TestOnly
#
# REQUIREMENTS:
#   - Script will prompt for domain credentials securely (no plaintext storage)
#   - Place your unique Vision One Endpoint Security Agent installer ZIP in the installer/ directory
#   - Run configure_target_machine.bat on target machines
#   - PowerShell execution policy: RemoteSigned or Bypass
#   - Domain admin privileges for target machines
#
# INSTALLER SETUP:
#   - Each user must download their own personalized Vision One Endpoint Security Agent installer
#   - The installer comes as a ZIP file from the Trend Micro Vision One portal
#   - Place the entire ZIP file in the installer/ directory (do not extract)
#   - Scripts will automatically extract the ZIP on target machines
#
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string[]]$TargetIPs,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetFile,
    
    [Parameter(Mandatory=$false)]
    [string]$CIDR,
    
    [switch]$TestOnly,
    [switch]$Parallel,
    [int]$MaxParallel = 5,
    [switch]$SkipExistingCheck,
    [switch]$ForceInstall
)

# Load configuration
. .\Config.ps1

# Initialize credentials with secure prompting
Write-Host "=== Vision One Endpoint Security Agent Deployment ===" -ForegroundColor Cyan
Write-Host ""

# Prompt for credentials directly (no caching/storage)
$Global:DeploymentCredential = $null
try {
    Write-Host "Please enter credentials for an account with administrator permissions on target machines" -ForegroundColor Yellow
    Write-Host "Format: DOMAIN\username (e.g., CONTOSO\admin)" -ForegroundColor Gray
    Write-Host ""
    
    $Global:DeploymentCredential = Get-Credential -Message "Enter deployment credentials (DOMAIN\username)"
    
    if (-not $Global:DeploymentCredential) {
        Write-Host "Deployment cancelled - credentials are required" -ForegroundColor Red
        exit 1
    }
    
    # Validate credential format and prompt for domain if needed
    if ($Global:DeploymentCredential.UserName -notmatch "\\") {
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
        $newUsername = "$domainName\$($Global:DeploymentCredential.UserName)"
        $Global:DeploymentCredential = New-Object System.Management.Automation.PSCredential($newUsername, $Global:DeploymentCredential.Password)
    }
    
    Write-Host "✓ Credentials loaded for user: $($Global:DeploymentCredential.UserName)" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "Failed to get credentials: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Override config with command-line parameters
if ($SkipExistingCheck) {
    $Global:DeploymentConfig.CheckExistingTrendMicro = $false
}

if ($ForceInstall) {
    $Global:DeploymentConfig.ForceInstallation = $true
}

function Test-InstallerAvailability {
    Write-Log "Validating installer availability..."
    
    $installerDir = $Global:DeploymentConfig.InstallerDirectory
    
    # Check if installer directory exists
    if (-not (Test-Path $installerDir)) {
        Write-Log "Installer directory not found: $installerDir" "ERROR"
        Write-Host ""
        Write-Host "SETUP REQUIRED:" -ForegroundColor Red
        Write-Host "1. Create the installer directory: $installerDir" -ForegroundColor Yellow
        Write-Host "2. Download your unique Vision One Endpoint Security Agent installer ZIP from Trend Micro Vision One portal" -ForegroundColor Yellow
        Write-Host "3. Place the ZIP file in the installer directory" -ForegroundColor Yellow
        Write-Host "4. Do NOT extract the ZIP file - scripts handle extraction automatically" -ForegroundColor Yellow
        return $false
    }
    
    # Check for ZIP files
    $zipFiles = Get-ChildItem -Path $installerDir -Filter "*.zip" -ErrorAction SilentlyContinue
    if ($zipFiles.Count -eq 0) {
        Write-Log "No ZIP files found in installer directory: $installerDir" "ERROR"
        Write-Host ""
        Write-Host "INSTALLER MISSING:" -ForegroundColor Red
        Write-Host "No Vision One Endpoint Security Agent installer ZIP files found in: $installerDir" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "REQUIRED STEPS:" -ForegroundColor Cyan
        Write-Host "1. Log into your Trend Micro Vision One portal" -ForegroundColor White
        Write-Host "2. Navigate to Endpoint Security > Agent Management" -ForegroundColor White
        Write-Host "3. Download your organization's unique installer package" -ForegroundColor White
        Write-Host "4. Place the downloaded ZIP file in: $installerDir" -ForegroundColor White
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
            Write-Log "Valid installer found: $($zipFile.Name) ($($zipFile.Length) bytes)" "SUCCESS"
        } catch {
            Write-Log "Invalid or corrupted ZIP file: $($zipFile.Name) - $($_.Exception.Message)" "WARNING"
        }
    }
    
    if ($validZips -eq 0) {
        Write-Log "No valid ZIP files found in installer directory" "ERROR"
        Write-Host ""
        Write-Host "ZIP FILE ISSUES:" -ForegroundColor Red
        Write-Host "Found ZIP files but they appear to be corrupted or invalid:" -ForegroundColor Yellow
        $zipFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Yellow }
        Write-Host ""
        Write-Host "SOLUTIONS:" -ForegroundColor Cyan
        Write-Host "1. Re-download the installer from Trend Micro Vision One portal" -ForegroundColor White
        Write-Host "2. Ensure the download completed successfully" -ForegroundColor White
        Write-Host "3. Check that the file is not corrupted (compare file size)" -ForegroundColor White
        return $false
    }
    
    Write-Log "Installer validation completed successfully - found $validZips valid installer(s)" "SUCCESS"
    return $true
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Test-HostConnectivity {
    param([string]$TargetIP)
    
    Write-Log "Testing connectivity to $TargetIP"
    
    # Test ping
    if (-not (Test-Connection -ComputerName $TargetIP -Count 1 -Quiet)) {
        Write-Log "Ping failed to $TargetIP" "ERROR"
        return $false
    }
    
    # Test SMB access
    try {
        $testPath = "\\$TargetIP\C$"
        if (Test-Path $testPath) {
            Write-Log "SMB access confirmed to $TargetIP" "SUCCESS"
            return $true
        } else {
            Write-Log "SMB access failed to $TargetIP" "ERROR"
            return $false
        }
    } catch {
        Write-Log "SMB access error to $TargetIP : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-WMIConnectivity {
    param([string]$TargetIP)
    
    Write-Log "Testing WMI connectivity to $TargetIP"
    
    try {
        $computer = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        Write-Log "WMI connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "WMI connection failed to $TargetIP : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Copy-InstallerFiles {
    param([string]$TargetIP)
    
    Write-Log "Copying and extracting installer files to $TargetIP"
    
    try {
        $sourceDir = $Global:DeploymentConfig.InstallerDirectory
        $targetDir = "\\$TargetIP\$($Global:DeploymentConfig.RemoteTempPath)"
        
        # Clean up existing files
        if (Test-Path $targetDir) {
            Remove-Item "$targetDir\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Create directory
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        
        # Find installer zip file with smart selection
        $zipFiles = Get-ChildItem -Path $sourceDir -Filter "*.zip" | Sort-Object LastWriteTime -Descending
        if ($zipFiles.Count -eq 0) {
            Write-Log "No zip files found in $sourceDir" "ERROR"
            return $false
        } elseif ($zipFiles.Count -gt 1) {
            Write-Log "Multiple zip files found in ${sourceDir}:" "WARNING"
            $zipFiles | ForEach-Object { Write-Log "  - $($_.Name) ($(Get-Date $_.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))" "WARNING" }
            
            # Smart selection: prefer files without (1), (2), etc. suffixes
            $preferredFile = $zipFiles | Where-Object { $_.Name -notmatch '\(\d+\)\.zip$' } | Select-Object -First 1
            if ($preferredFile) {
                $zipFile = $preferredFile
                Write-Log "Selected: $($zipFile.Name) (original filename without duplicate suffix)" "SUCCESS"
            } else {
                # If all files have duplicate suffixes, use the most recent one
                $zipFile = $zipFiles[0]
                Write-Log "Selected: $($zipFile.Name) (most recent file)" "SUCCESS"
            }
        } else {
            $zipFile = $zipFiles[0]
        }
        Write-Log "Found installer zip: $($zipFile.Name) ($($zipFile.Length) bytes)"
        
        # Copy zip file to target
        $targetZipPath = "$targetDir\$($zipFile.Name)"
        Copy-Item -Path $zipFile.FullName -Destination $targetZipPath -Force
        Write-Log "Copied zip file to target machine"
        
        # Extract zip file on target machine using PowerShell remoting
        $extractionResult = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
            param($ZipPath, $ExtractPath)
            
            try {
                # Ensure extraction directory exists
                if (-not (Test-Path $ExtractPath)) {
                    New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null
                }
                
                # Extract using .NET System.IO.Compression
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractPath)
                
                # Verify extraction
                $extractedFiles = Get-ChildItem -Path $ExtractPath -Recurse -File
                Write-Output "Successfully extracted $($extractedFiles.Count) files"
                
                # Look for main executable
                $mainExe = Get-ChildItem -Path $ExtractPath -Name "*.exe" -Recurse | Select-Object -First 1
                if ($mainExe) {
                    Write-Output "Main executable found: $mainExe"
                    return @{
                        Success = $true
                        FileCount = $extractedFiles.Count
                        MainExecutable = $mainExe
                    }
                } else {
                    Write-Output "Warning: No executable found in extracted files"
                    return @{
                        Success = $true
                        FileCount = $extractedFiles.Count
                        MainExecutable = $null
                    }
                }
                
            } catch {
                Write-Error "Extraction failed: $($_.Exception.Message)"
                return @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        } -ArgumentList "C:\temp\Trend Micro\V1ES\$($zipFile.Name)", "C:\temp\Trend Micro\V1ES"
        
        if ($extractionResult.Success) {
            Write-Log "Successfully extracted $($extractionResult.FileCount) files on $TargetIP" "SUCCESS"
            if ($extractionResult.MainExecutable) {
                Write-Log "Main executable: $($extractionResult.MainExecutable)" "SUCCESS"
                
                # Update the installer command in config to use the found executable
                $Global:DeploymentConfig.InstallerCommand = "C:\temp\Trend Micro\V1ES\$($extractionResult.MainExecutable) /S /v`"/quiet /norestart`""
            }
            
            # Clean up zip file
            Remove-Item $targetZipPath -Force -ErrorAction SilentlyContinue
            
            return $true
        } else {
            Write-Log "Extraction failed on $TargetIP : $($extractionResult.Error)" "ERROR"
            return $false
        }
        
    } catch {
        Write-Log "File copy and extraction failed to $TargetIP : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-Installation {
    param([string]$TargetIP)
    
    Write-Log "Starting installation on $TargetIP"
    
    try {
        $installCommand = $Global:DeploymentConfig.InstallerCommand
        
        $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $installCommand -ComputerName $TargetIP -Credential $Global:DeploymentCredential
        
        if ($result.ReturnValue -eq 0) {
            Write-Log "Installation started successfully on $TargetIP (ProcessId: $($result.ProcessId))" "SUCCESS"
            return $result.ProcessId
        } else {
            Write-Log "Installation failed to start on $TargetIP (Return code: $($result.ReturnValue))" "ERROR"
            return $null
        }
    } catch {
        Write-Log "Installation error on $TargetIP : $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Monitor-Installation {
    param([string]$TargetIP, [int]$ProcessId)
    
    Write-Log "Monitoring installation on $TargetIP (ProcessId: $ProcessId)"
    
    $maxCycles = $Global:DeploymentConfig.MaxMonitoringCycles
    $interval = $Global:DeploymentConfig.MonitoringInterval
    
    for ($i = 1; $i -le $maxCycles; $i++) {
        Start-Sleep -Seconds $interval
        
        try {
            $processes = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
            
            if ($processes) {
                Write-Log "[$i/$maxCycles] Installation still running on $TargetIP"
            } else {
                Write-Log "[$i/$maxCycles] Installation process completed on $TargetIP" "SUCCESS"
                break
            }
        } catch {
            Write-Log "[$i/$maxCycles] Error monitoring $TargetIP : $($_.Exception.Message)" "WARNING"
        }
    }
}

function Test-ExistingTrendMicro {
    param([string]$TargetIP)
    
    Write-Log "Checking for existing Trend Micro products on $TargetIP"
    
    try {
        # Check for Trend Micro processes
        $trendProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
            $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or 
            $_.Name -like "*Endpoint*" -or $_.Name -like "*TMCCSF*" -or $_.Name -like "*ntrtscan*" -or
            $_.Name -like "*TmListen*" -or $_.Name -like "*TmProxy*"
        }
        
        # Check for installed Trend Micro software via WMI
        $installedSoftware = Get-WmiObject -Class Win32_Product -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object {
            $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*Vision One*" -or
            $_.Name -like "*Endpoint*" -and $_.Name -like "*Trend*"
        }
        
        $existingProducts = @()
        
        if ($trendProcesses) {
            Write-Log "Existing Trend Micro processes found on $TargetIP :" "WARNING"
            $trendProcesses | ForEach-Object { 
                Write-Log "  - Process: $($_.Name) (PID: $($_.ProcessId))" "WARNING"
                $existingProducts += "Process: $($_.Name)"
            }
        }
        
        if ($installedSoftware) {
            Write-Log "Existing Trend Micro software found on $TargetIP :" "WARNING"
            $installedSoftware | ForEach-Object { 
                Write-Log "  - Software: $($_.Name) (Version: $($_.Version))" "WARNING"
                $existingProducts += "Software: $($_.Name)"
            }
        }
        
        if ($existingProducts.Count -gt 0) {
            Write-Log "Found $($existingProducts.Count) existing Trend Micro components on $TargetIP" "WARNING"
            return @{
                HasExisting = $true
                Products = $existingProducts
            }
        } else {
            Write-Log "No existing Trend Micro products detected on $TargetIP" "SUCCESS"
            return @{
                HasExisting = $false
                Products = @()
            }
        }
        
    } catch {
        Write-Log "Error checking existing products on $TargetIP : $($_.Exception.Message)" "ERROR"
        return @{
            HasExisting = $false
            Products = @()
            Error = $_.Exception.Message
        }
    }
}

function Test-InstallationSuccess {
    param([string]$TargetIP)
    
    Write-Log "Checking for Vision One processes on $TargetIP"
    
    try {
        $visionProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
            $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
        }
        
        if ($visionProcesses) {
            Write-Log "Vision One processes detected on $TargetIP :" "SUCCESS"
            $visionProcesses | ForEach-Object { Write-Log "  - $($_.Name) (PID: $($_.ProcessId))" }
            return $true
        } else {
            Write-Log "No Vision One processes detected on $TargetIP" "WARNING"
            return $false
        }
    } catch {
        Write-Log "Error checking processes on $TargetIP : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Deploy-ToSingleHost {
    param([string]$TargetIP)
    
    Write-Log "=== Starting deployment to $TargetIP ===" "INFO"
    
    # Test connectivity
    if (-not (Test-HostConnectivity $TargetIP)) {
        return $false
    }
    
    if (-not (Test-WMIConnectivity $TargetIP)) {
        return $false
    }
    
    # Check for existing Trend Micro products
    if ($Global:DeploymentConfig.CheckExistingTrendMicro) {
        $existingCheck = Test-ExistingTrendMicro $TargetIP
        
        if ($existingCheck.HasExisting) {
            Write-Log "Existing Trend Micro products detected on $TargetIP" "WARNING"
            $existingCheck.Products | ForEach-Object { Write-Log "  - $_" "WARNING" }
            
            if ($Global:DeploymentConfig.SkipIfExisting -and -not $Global:DeploymentConfig.ForceInstallation) {
                Write-Log "Skipping installation on $TargetIP due to existing products (SkipIfExisting = true)" "WARNING"
                return $true  # Consider this a "success" since we're intentionally skipping
            } elseif (-not $Global:DeploymentConfig.ForceInstallation) {
                Write-Log "Proceeding with installation on $TargetIP despite existing products" "WARNING"
                Write-Log "Set ForceInstallation = true in Config.ps1 to suppress this warning" "INFO"
            } else {
                Write-Log "Force installation enabled - proceeding with installation on $TargetIP" "INFO"
            }
        } else {
            Write-Log "No existing Trend Micro products found on $TargetIP - proceeding with installation" "SUCCESS"
        }
    }
    
    if ($TestOnly) {
        Write-Log "Test-only mode: All tests passed for $TargetIP" "SUCCESS"
        return $true
    }
    
    # Copy files
    if (-not (Copy-InstallerFiles $TargetIP)) {
        return $false
    }
    
    # Start installation
    $processId = Start-Installation $TargetIP
    if (-not $processId) {
        return $false
    }
    
    # Monitor installation
    Monitor-Installation $TargetIP $processId
    
    # Check for success
    $success = Test-InstallationSuccess $TargetIP
    
    if ($success) {
        Write-Log "=== Deployment completed successfully for $TargetIP ===" "SUCCESS"
    } else {
        Write-Log "=== Deployment may have failed for $TargetIP ===" "WARNING"
    }
    
    return $success
}

function Get-NetworkHosts {
    param([string]$CIDR)
    
    Write-Log "Scanning network: $CIDR"
    
    try {
        # Parse CIDR notation (e.g., 10.0.5.0/24)
        if ($CIDR -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
            $networkIP = $matches[1]
            $subnetMask = [int]$matches[2]
        } else {
            throw "Invalid CIDR format. Use format like 10.0.5.0/24"
        }
        
        # Convert IP to integer
        $ipParts = $networkIP.Split('.')
        $networkInt = ([uint32]$ipParts[0] -shl 24) + ([uint32]$ipParts[1] -shl 16) + ([uint32]$ipParts[2] -shl 8) + [uint32]$ipParts[3]
        
        # Calculate network range
        $hostBits = 32 - $subnetMask
        $networkMask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, $hostBits))
        $networkAddress = $networkInt -band $networkMask
        $broadcastAddress = $networkAddress + [Math]::Pow(2, $hostBits) - 1
        
        # Generate host IPs
        $hostIPs = @()
        
        if ($subnetMask -eq 32) {
            # /32 is a single host
            $hostIPs += $networkIP
            Write-Log "Single host: $networkIP"
        } elseif ($subnetMask -eq 31) {
            # /31 has 2 hosts (no network/broadcast)
            for ($i = $networkAddress; $i -le $broadcastAddress; $i++) {
                $ip = "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
                $hostIPs += $ip
            }
        } else {
            # Normal networks (skip network and broadcast addresses)
            for ($i = $networkAddress + 1; $i -lt $broadcastAddress; $i++) {
                $ip = "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
                $hostIPs += $ip
            }
        }
        
        Write-Log "Network range: $($hostIPs.Count) possible hosts ($($hostIPs[0]) - $($hostIPs[-1]))"
        
        # Ping sweep to find live hosts
        Write-Log "Performing ping sweep (this may take a few minutes)..."
        $liveHosts = @()
        $maxConcurrent = $Global:DeploymentConfig.MaxConcurrentPings
        $jobs = @()
        
        foreach ($ip in $hostIPs) {
            # Limit concurrent jobs
            while ((Get-Job -State Running).Count -ge $maxConcurrent) {
                Start-Sleep -Milliseconds 100
            }
            
            $job = Start-Job -ScriptBlock {
                param($targetIP, $timeout)
                if (Test-Connection -ComputerName $targetIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    return $targetIP
                }
                return $null
            } -ArgumentList $ip, $Global:DeploymentConfig.PingTimeout
            
            $jobs += $job
        }
        
        # Wait for all jobs and collect results
        Write-Log "Waiting for ping sweep to complete..."
        $jobs | Wait-Job | Out-Null
        
        foreach ($job in $jobs) {
            $result = Receive-Job $job
            if ($result) {
                $liveHosts += $result
            }
            Remove-Job $job
        }
        
        Write-Log "Found $($liveHosts.Count) live hosts in $CIDR"
        
        # Filter for Windows hosts if requested
        if ($Global:DeploymentConfig.ScanOnlyWindowsHosts -and $liveHosts.Count -gt 0) {
            Write-Log "Filtering for Windows hosts (this may take additional time)..."
            $windowsHosts = @()
            
            foreach ($targetHost in $liveHosts) {
                try {
                    # Try to access admin share (Windows-specific)
                    if (Test-Path "\\$targetHost\C$" -ErrorAction SilentlyContinue) {
                        $windowsHosts += $targetHost
                        Write-Log "  - $targetHost (Windows detected)" "SUCCESS"
                    } else {
                        Write-Log "  - $targetHost (Not Windows or access denied)" "WARNING"
                    }
                } catch {
                    Write-Log "  - $targetHost (Not Windows or access denied)" "WARNING"
                }
            }
            
            Write-Log "Found $($windowsHosts.Count) Windows hosts out of $($liveHosts.Count) live hosts" "SUCCESS"
            $liveHosts = $windowsHosts
        } else {
            $liveHosts | ForEach-Object { Write-Log "  - $_" }
        }
        
        return $liveHosts
        
    } catch {
        Write-Log "Error scanning network $CIDR : $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-TargetHosts {
    $hosts = @()
    
    if ($TargetIPs) {
        $hosts += $TargetIPs
    }
    
    if ($TargetFile -and (Test-Path $TargetFile)) {
        $hosts += Get-Content $TargetFile | Where-Object { $_ -and $_.Trim() -ne "" -and -not $_.StartsWith('#') }
    }
    
    if ($CIDR) {
        $networkHosts = Get-NetworkHosts $CIDR
        $hosts += $networkHosts
    }
    
    return $hosts | Sort-Object -Unique
}

# Main execution
Write-Host "=== Vision One Endpoint Security Agent Deployment Tool - PowerShell Edition ===" -ForegroundColor Cyan
Write-Host "Configuration loaded from Config.ps1" -ForegroundColor White
Write-Host ""

# Early validation - check for installer before doing anything else
if (-not (Test-InstallerAvailability)) {
    Write-Host ""
    Write-Host "❌ Deployment cannot proceed without a valid installer." -ForegroundColor Red
    Write-Host "Please follow the setup instructions above and try again." -ForegroundColor Yellow
    exit 1
}

$targetHosts = Get-TargetHosts

if (-not $targetHosts) {
    Write-Host "IMPORTANT: Place your Vision One Endpoint Security Agent installer ZIP in the installer/ directory first!" -ForegroundColor Red
    Write-Host "Each user must download their own unique installer from Trend Micro Vision One portal." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Usage Examples:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128','10.0.5.129'"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt'"
    Write-Host "  .\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24'"
    Write-Host "  .\Deploy-VisionOne.ps1 -CIDR '192.168.1.0/24' -Parallel -MaxParallel 5"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -TestOnly"
    Write-Host "  .\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -TestOnly"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -SkipExistingCheck"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -ForceInstall"
    Write-Host ""
    Write-Host "Parameters:" -ForegroundColor Cyan
    Write-Host "  -CIDR              : Network range in CIDR notation (e.g., 10.0.5.0/24)"
    Write-Host "  -TargetIPs         : Specific IP addresses to target"
    Write-Host "  -TargetFile        : File containing IP addresses (one per line)"
    Write-Host "  -SkipExistingCheck : Skip checking for existing Trend Micro products"
    Write-Host "  -ForceInstall      : Install even if existing Trend Micro products found"
    Write-Host "  -TestOnly          : Test connectivity only, don't deploy"
    Write-Host "  -Parallel          : Deploy to multiple hosts simultaneously"
    Write-Host "  -MaxParallel       : Maximum parallel deployments (default: 5)"
    Write-Host ""
    Write-Host "Network Scanning:" -ForegroundColor Cyan
    Write-Host "  Edit Config.ps1 to configure network scanning options:"
    Write-Host "  - MaxConcurrentPings: Concurrent ping operations (default: 50)"
    Write-Host "  - ScanOnlyWindowsHosts: Filter for Windows hosts only (slower)"
    Write-Host ""
    exit 1
}

Write-Log "Target hosts: $($targetHosts -join ', ')"
Write-Log "Test only: $TestOnly"
Write-Log "Parallel: $Parallel"

$results = @()
$startTime = Get-Date

if ($Parallel -and $targetHosts.Count -gt 1) {
    Write-Log "Starting parallel deployment to $($targetHosts.Count) hosts (max parallel: $MaxParallel)"
    
    $jobs = @()
    foreach ($targetHost in $targetHosts) {
        while ((Get-Job -State Running).Count -ge $MaxParallel) {
            Start-Sleep -Seconds 5
        }
        
        $job = Start-Job -ScriptBlock {
            param($targetHost, $configPath)
            . $configPath
            Deploy-ToSingleHost $targetHost
        } -ArgumentList $targetHost, (Resolve-Path ".\Config.ps1")
        
        $jobs += $job
        Write-Log "Started job for $targetHost (Job ID: $($job.Id))"
    }
    
    # Wait for all jobs to complete
    Write-Log "Waiting for all jobs to complete..."
    $jobs | Wait-Job | Out-Null
    
    # Collect results
    foreach ($job in $jobs) {
        $result = Receive-Job $job
        $results += $result
        Remove-Job $job
    }
    
} else {
    # Sequential deployment
    foreach ($targetHost in $targetHosts) {
        $success = Deploy-ToSingleHost $targetHost
        $results += $success
        Write-Host ""
    }
}

# Summary
$endTime = Get-Date
$duration = $endTime - $startTime
$successful = ($results | Where-Object { $_ -eq $true }).Count
$failed = $targetHosts.Count - $successful

Write-Host "=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "Total hosts: $($targetHosts.Count)" -ForegroundColor White
Write-Host "Successful: $successful" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host ""

if ($failed -eq 0) {
    Write-Host "🎉 All deployments completed successfully!" -ForegroundColor Green
} else {
    Write-Host "⚠️  Some deployments failed. Check the logs above." -ForegroundColor Yellow
}