# ============================================================================
# VisionOne SEP Deployment Script - Primary Deployment Engine
# ============================================================================
# 
# PURPOSE: Full-featured deployment script for Trend Micro VisionOne SEP
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
#   - Edit Config.ps1 with your domain credentials before use
#   - Run configure_target_machine.bat on target machines
#   - PowerShell execution policy: RemoteSigned or Bypass
#   - Domain admin privileges for target machines
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

# Override config with command-line parameters
if ($SkipExistingCheck) {
    $Global:DeploymentConfig.CheckExistingTrendMicro = $false
}

if ($ForceInstall) {
    $Global:DeploymentConfig.ForceInstallation = $true
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
        $cred = Get-DeploymentCredentials
        $computer = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $TargetIP -Credential $cred -ErrorAction Stop
        Write-Log "WMI connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "WMI connection failed to $TargetIP : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Copy-InstallerFiles {
    param([string]$TargetIP)
    
    Write-Log "Copying installer files to $TargetIP"
    
    try {
        $sourceDir = $Global:DeploymentConfig.InstallerDirectory
        $targetDir = "\\$TargetIP\$($Global:DeploymentConfig.RemoteTempPath)"
        
        # Clean up existing files
        if (Test-Path $targetDir) {
            Remove-Item "$targetDir\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Create directory and copy files
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        Copy-Item -Path "$sourceDir\*" -Destination $targetDir -Recurse -Force
        
        # Verify copy
        $mainExe = "$targetDir\EndpointBasecamp.exe"
        if (Test-Path $mainExe) {
            $fileSize = (Get-Item $mainExe).Length
            $fileCount = (Get-ChildItem $targetDir -Recurse -File).Count
            Write-Log "Successfully copied $fileCount files to $TargetIP (main exe: $fileSize bytes)" "SUCCESS"
            return $true
        } else {
            Write-Log "Main executable not found after copy to $TargetIP" "ERROR"
            return $false
        }
    } catch {
        Write-Log "File copy failed to $TargetIP : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-Installation {
    param([string]$TargetIP)
    
    Write-Log "Starting installation on $TargetIP"
    
    try {
        $cred = Get-DeploymentCredentials
        $installCommand = $Global:DeploymentConfig.InstallerCommand
        
        $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $installCommand -ComputerName $TargetIP -Credential $cred
        
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
    
    $cred = Get-DeploymentCredentials
    $maxCycles = $Global:DeploymentConfig.MaxMonitoringCycles
    $interval = $Global:DeploymentConfig.MonitoringInterval
    
    for ($i = 1; $i -le $maxCycles; $i++) {
        Start-Sleep -Seconds $interval
        
        try {
            $processes = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
            
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
        $cred = Get-DeploymentCredentials
        
        # Check for Trend Micro processes
        $trendProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred | Where-Object { 
            $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or 
            $_.Name -like "*Endpoint*" -or $_.Name -like "*TMCCSF*" -or $_.Name -like "*ntrtscan*" -or
            $_.Name -like "*TmListen*" -or $_.Name -like "*TmProxy*"
        }
        
        # Check for installed Trend Micro software via WMI
        $installedSoftware = Get-WmiObject -Class Win32_Product -ComputerName $TargetIP -Credential $cred | Where-Object {
            $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*VisionOne*" -or
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
    
    Write-Log "Checking for VisionOne processes on $TargetIP"
    
    try {
        $cred = Get-DeploymentCredentials
        $visionProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $cred | Where-Object { 
            $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
        }
        
        if ($visionProcesses) {
            Write-Log "VisionOne processes detected on $TargetIP :" "SUCCESS"
            $visionProcesses | ForEach-Object { Write-Log "  - $($_.Name) (PID: $($_.ProcessId))" }
            return $true
        } else {
            Write-Log "No VisionOne processes detected on $TargetIP" "WARNING"
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
Write-Host "=== VisionOne SEP Deployment Tool - PowerShell Edition ===" -ForegroundColor Cyan
Write-Host "Configuration loaded from Config.ps1" -ForegroundColor White
Write-Host ""

$targetHosts = Get-TargetHosts

if (-not $targetHosts) {
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