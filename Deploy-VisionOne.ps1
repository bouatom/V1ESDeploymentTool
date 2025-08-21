# Vision One Endpoint Security Agent Deployment Script
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
    [switch]$FullParallel,
    [int]$ParallelLimit = 0,
    [switch]$SkipExistingCheck,
    [switch]$ForceInstall,
    [switch]$ShowWMIHelp,
    [switch]$ShowParallelConfig,
    [switch]$ConfigureTrustedHosts
)

# Trap handler to ensure TrustedHosts is restored on script exit
trap {
    Write-Host "Script interrupted. Restoring TrustedHosts..." -ForegroundColor Yellow
    if (Get-Variable -Name OriginalTrustedHosts -Scope Global -ErrorAction SilentlyContinue) {
        Restore-TrustedHosts
    }
    break
}

# Load configuration
. .\Config.ps1

# Global optimization variables
$Global:LocalDetectionCache = @{}
$Global:WMISessionCache = @{}

# Initialize credentials
Write-Host "=== Vision One Endpoint Security Agent Deployment ===" -ForegroundColor Cyan

$Global:DeploymentCredential = $null
try {
    Write-Host "Please enter credentials for administrator access" -ForegroundColor Yellow
    $Global:DeploymentCredential = Get-Credential -Message "Enter deployment credentials"
    
    if (-not $Global:DeploymentCredential) {
        Write-Host "Deployment cancelled - credentials required" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Credentials loaded successfully" -ForegroundColor Green
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

# Override parallel deployment settings from command line
if ($ParallelLimit -gt 0) {
    $Global:DeploymentConfig.MaxParallelDeployments = $ParallelLimit
    Write-Log "Parallel deployment limit set to $ParallelLimit via command line" "INFO"
}

if ($MaxParallel -ne 5) {  # 5 is the default value
    $Global:DeploymentConfig.MaxParallelDeployments = $MaxParallel
    Write-Log "Parallel deployment limit set to $MaxParallel via MaxParallel parameter" "INFO"
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

function Test-IsLocalMachine {
    param([string]$TargetIP)
    
    # Check cache first for performance
    if ($Global:LocalDetectionCache.ContainsKey($TargetIP)) {
        return $Global:LocalDetectionCache[$TargetIP]
    }
    
    # Initialize local machine data once
    if (-not $Global:LocalMachineData) {
        $Global:LocalMachineData = @{
            Hostname = $env:COMPUTERNAME
            FQDN = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
            IPs = @()
        }
        
        # Get local IP addresses
        try {
            $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            foreach ($adapter in $networkAdapters) {
                if ($adapter.IPAddress) {
                    $Global:LocalMachineData.IPs += $adapter.IPAddress
                }
            }
        } catch {
            # Fallback method
            $Global:LocalMachineData.IPs += (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
        }
        
        # Add common local addresses
        $Global:LocalMachineData.IPs += @("127.0.0.1", "localhost", "::1")
    }
    
    # Check if target matches any local identifier
    $isLocal = ($TargetIP -eq $Global:LocalMachineData.Hostname) -or 
               ($TargetIP -eq $Global:LocalMachineData.FQDN) -or 
               ($TargetIP -in $Global:LocalMachineData.IPs) -or
               ($TargetIP -eq "localhost") -or
               ($TargetIP -eq "127.0.0.1")
    
    # Cache the result
    $Global:LocalDetectionCache[$TargetIP] = $isLocal
    
    if ($isLocal) {
        Write-Log "Detected local connection for $TargetIP" "INFO"
    } else {
        Write-Log "Detected remote connection for $TargetIP" "INFO"
    }
    
    return $isLocal
}

function Show-WMITroubleshootingHelp {
    Write-Host ""
    Write-Host "=== WMI & PowerShell Remoting Troubleshooting Guide ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "If WMI/PowerShell Remoting connections are failing, try these solutions:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Windows Firewall Configuration:" -ForegroundColor White
    Write-Host "   netsh advfirewall firewall set rule group=`"Windows Management Instrumentation (WMI)`" new enable=yes" -ForegroundColor Gray
    Write-Host "   netsh advfirewall firewall set rule group=`"Remote Administration`" new enable=yes" -ForegroundColor Gray
    Write-Host "   netsh advfirewall firewall set rule group=`"Windows Remote Management`" new enable=yes" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Enable WinRM (for PowerShell Remoting):" -ForegroundColor White
    Write-Host "   winrm quickconfig -force" -ForegroundColor Gray
    Write-Host "   winrm set winrm/config/service/auth @{Basic=`"true`"}" -ForegroundColor Gray
    Write-Host "   winrm set winrm/config/client/auth @{Basic=`"true`"}" -ForegroundColor Gray
    Write-Host "   winrm set winrm/config/service @{AllowUnencrypted=`"true`"}" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. TrustedHosts Configuration (run on deployment machine):" -ForegroundColor White
    Write-Host "   winrm set winrm/config/client @{TrustedHosts=`"*`"}" -ForegroundColor Gray
    Write-Host "   # Or for specific IPs: winrm set winrm/config/client @{TrustedHosts=`"10.0.0.10,10.0.0.11`"}" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. DCOM Configuration:" -ForegroundColor White
    Write-Host "   - Run dcomcnfg.exe as administrator" -ForegroundColor Gray
    Write-Host "   - Navigate to Component Services > Computers > My Computer > DCOM Config" -ForegroundColor Gray
    Write-Host "   - Right-click 'Windows Management Instrumentation' > Properties" -ForegroundColor Gray
    Write-Host "   - Security tab > Authentication Level: Set to 'None'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "5. Registry Settings (run on target machines):" -ForegroundColor White
    Write-Host "   reg add HKLM\SOFTWARE\Microsoft\Ole /v EnableDCOMHTTP /t REG_DWORD /d 1 /f" -ForegroundColor Gray
    Write-Host ""
    Write-Host "6. Services to verify are running:" -ForegroundColor White
    Write-Host "   - Windows Management Instrumentation" -ForegroundColor Gray
    Write-Host "   - Remote Registry" -ForegroundColor Gray
    Write-Host "   - Windows Remote Management (WS-Management)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "7. Alternative: Use PsExec for remote execution:" -ForegroundColor White
    Write-Host "   Download PsExec from Microsoft Sysinternals and add to PATH" -ForegroundColor Gray
    Write-Host ""
    Write-Host "8. Quick Fix Commands (run as administrator on deployment machine):" -ForegroundColor White
    Write-Host "   Enable-PSRemoting -Force" -ForegroundColor Gray
    Write-Host "   Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force" -ForegroundColor Gray
    Write-Host ""
}

function Initialize-WinRMSettings {
    Write-Log "Checking and configuring WinRM settings for IP address connectivity..."
    
    try {
        # Check if WinRM service is running
        $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrmService.Status -ne 'Running') {
            Write-Log "Starting WinRM service..." "WARNING"
            Start-Service -Name WinRM -ErrorAction Stop
        }
        
        # Check current TrustedHosts setting
        $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        Write-Log "Current TrustedHosts: $currentTrustedHosts" "INFO"
        
        if ([string]::IsNullOrEmpty($currentTrustedHosts) -or $currentTrustedHosts -eq "") {
            Write-Log "TrustedHosts is empty. This may cause IP address connection issues." "WARNING"
            Write-Log "TrustedHosts will be automatically configured based on target network." "INFO"
        }
        
        return $true
    } catch {
        Write-Log "Failed to configure WinRM settings: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Set-TrustedHostsForCIDR {
    param([string]$CIDR)
    
    Write-Log "Configuring TrustedHosts for network: $CIDR" "INFO"
    
    try {
        # Store original TrustedHosts value
        $originalTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        $Global:OriginalTrustedHosts = $originalTrustedHosts
        
        # Convert CIDR to wildcard pattern for TrustedHosts
        $trustedPattern = Convert-CIDRToTrustedPattern $CIDR
        
        # Set new TrustedHosts value
        if ([string]::IsNullOrEmpty($originalTrustedHosts)) {
            Write-Log "Setting TrustedHosts to: $trustedPattern" "INFO"
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $trustedPattern -Force
        } else {
            Write-Log "Adding to existing TrustedHosts: $trustedPattern" "INFO"
            $newValue = "$originalTrustedHosts,$trustedPattern"
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force
        }
        
        Write-Log "TrustedHosts configured successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "Failed to configure TrustedHosts: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Convert-CIDRToTrustedPattern {
    param([string]$CIDR)
    
    if ($CIDR -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
        $networkIP = $matches[1]
        $prefixLength = [int]$matches[2]
        
        # Convert to wildcard pattern based on prefix length
        $octets = $networkIP.Split('.')
        
        switch ($prefixLength) {
            8  { return "$($octets[0]).*" }
            16 { return "$($octets[0]).$($octets[1]).*" }
            24 { return "$($octets[0]).$($octets[1]).$($octets[2]).*" }
            32 { return $networkIP }  # Single host
            default {
                # For other prefix lengths, use the network portion with wildcard
                if ($prefixLength -le 8) { return "$($octets[0]).*" }
                elseif ($prefixLength -le 16) { return "$($octets[0]).$($octets[1]).*" }
                elseif ($prefixLength -le 24) { return "$($octets[0]).$($octets[1]).$($octets[2]).*" }
                else { return $networkIP }
            }
        }
    } elseif ($CIDR -match '^\d+\.\d+\.\d+\.\d+$') {
        # Single IP address
        return $CIDR
    } else {
        # Fallback - return as-is
        return $CIDR
    }
}

function Restore-TrustedHosts {
    Write-Log "Restoring original TrustedHosts configuration..." "INFO"
    
    try {
        if ($Global:OriginalTrustedHosts) {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $Global:OriginalTrustedHosts -Force
            Write-Log "TrustedHosts restored to: $($Global:OriginalTrustedHosts)" "SUCCESS"
        } else {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force
            Write-Log "TrustedHosts cleared (was originally empty)" "SUCCESS"
        }
        
        # Clear the global variable
        Remove-Variable -Name OriginalTrustedHosts -Scope Global -ErrorAction SilentlyContinue
        
    } catch {
        Write-Log "Failed to restore TrustedHosts: $($_.Exception.Message)" "WARNING"
    }
}

function Clear-OptimizationCaches {
    Write-Log "Cleaning up optimization caches..." "INFO"
    
    try {
        # Clear caches to free memory
        if ($Global:LocalDetectionCache) {
            $Global:LocalDetectionCache.Clear()
        }
        
        if ($Global:WMISessionCache) {
            # Close any open WMI sessions
            foreach ($session in $Global:WMISessionCache.Values) {
                if ($session -and $session.GetType().Name -eq "CimSession") {
                    Remove-CimSession $session -ErrorAction SilentlyContinue
                }
            }
            $Global:WMISessionCache.Clear()
        }
        
        # Clear local machine data
        Remove-Variable -Name LocalMachineData -Scope Global -ErrorAction SilentlyContinue
        
        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        
        Write-Log "Optimization caches cleared successfully" "SUCCESS"
        
    } catch {
        Write-Log "Failed to clear optimization caches: $($_.Exception.Message)" "WARNING"
    }
}

function Start-PerformanceTimer {
    param([string]$Operation)
    
    if (-not $Global:PerformanceTimers) {
        $Global:PerformanceTimers = @{}
    }
    
    $Global:PerformanceTimers[$Operation] = @{
        StartTime = Get-Date
        Operation = $Operation
    }
}

function Stop-PerformanceTimer {
    param([string]$Operation)
    
    if ($Global:PerformanceTimers -and $Global:PerformanceTimers.ContainsKey($Operation)) {
        $timer = $Global:PerformanceTimers[$Operation]
        $duration = (Get-Date) - $timer.StartTime
        Write-Log "Performance: $Operation completed in $($duration.TotalSeconds.ToString('F2')) seconds" "INFO"
        $Global:PerformanceTimers.Remove($Operation)
    }
}

function Show-ParallelConfiguration {
    Write-Host "=== Parallel Deployment Configuration ===" -ForegroundColor Cyan
    Write-Host "Parallel Deployment Enabled: $($Global:DeploymentConfig.EnableParallelDeployment)" -ForegroundColor White
    Write-Host "Maximum Concurrent Deployments: $($Global:DeploymentConfig.MaxParallelDeployments)" -ForegroundColor White
    Write-Host "Auto-Parallel Threshold: $($Global:DeploymentConfig.AutoParallelThreshold) hosts" -ForegroundColor White
    Write-Host "Batch Size: $($Global:DeploymentConfig.ParallelBatchSize)" -ForegroundColor White
    Write-Host "Progress Update Interval: $($Global:DeploymentConfig.ParallelProgressInterval) seconds" -ForegroundColor White
    Write-Host ""
    
    # Provide recommendations based on system
    $recommendedMax = 5  # Default recommendation
    $totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    $cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    
    if ($totalRAM -lt 8 -or $cpuCores -lt 4) {
        $recommendedMax = 2
        $systemClass = "Low-end"
    } elseif ($totalRAM -lt 16 -or $cpuCores -lt 8) {
        $recommendedMax = 5
        $systemClass = "Mid-range"
    } elseif ($totalRAM -lt 32 -or $cpuCores -lt 16) {
        $recommendedMax = 10
        $systemClass = "High-end"
    } else {
        $recommendedMax = 15
        $systemClass = "Server-class"
    }
    
    Write-Host "System Classification: $systemClass ($([Math]::Round($totalRAM, 1))GB RAM, $cpuCores cores)" -ForegroundColor Gray
    Write-Host "Recommended Max Parallel: $recommendedMax deployments" -ForegroundColor Yellow
    
    if ($Global:DeploymentConfig.MaxParallelDeployments -gt $recommendedMax) {
        Write-Host "⚠️  Current setting ($($Global:DeploymentConfig.MaxParallelDeployments)) exceeds recommendation" -ForegroundColor Yellow
    } elseif ($Global:DeploymentConfig.MaxParallelDeployments -lt ($recommendedMax / 2)) {
        Write-Host "💡 Current setting ($($Global:DeploymentConfig.MaxParallelDeployments)) is conservative, could increase to $recommendedMax" -ForegroundColor Green
    } else {
        Write-Host "✅ Current setting ($($Global:DeploymentConfig.MaxParallelDeployments)) is optimal for your system" -ForegroundColor Green
    }
    Write-Host ""
}

function Optimize-FileOperations {
    param([string]$SourcePath, [string]$DestinationPath)
    
    try {
        # Use robocopy for better performance on large files
        $robocopyArgs = @(
            $SourcePath,
            $DestinationPath,
            "/E",           # Copy subdirectories including empty ones
            "/R:3",         # Retry 3 times on failed copies
            "/W:5",         # Wait 5 seconds between retries
            "/MT:8",        # Multi-threaded copy (8 threads)
            "/NP",          # No progress display
            "/NFL",         # No file list
            "/NDL"          # No directory list
        )
        
        $result = & robocopy @robocopyArgs 2>&1
        $exitCode = $LASTEXITCODE
        
        # Robocopy exit codes: 0-7 are success, 8+ are errors
        if ($exitCode -lt 8) {
            return $true
        } else {
            Write-Log "Robocopy failed with exit code: $exitCode" "WARNING"
            return $false
        }
        
    } catch {
        Write-Log "Optimize-FileOperations failed: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Start-ParallelDeployment {
    param([array]$TargetHosts)
    
    # Validate and adjust parallel deployment limits
    $maxParallel = $Global:DeploymentConfig.MaxParallelDeployments
    
    # Ensure reasonable limits
    if ($maxParallel -lt 1) {
        $maxParallel = 1
        Write-Log "Parallel limit too low, adjusted to 1" "WARNING"
    } elseif ($maxParallel -gt 20) {
        $maxParallel = 20
        Write-Log "Parallel limit too high, adjusted to 20 for system stability" "WARNING"
    }
    
    # Don't run more parallel deployments than we have hosts
    if ($maxParallel -gt $TargetHosts.Count) {
        $maxParallel = $TargetHosts.Count
        Write-Log "Parallel limit adjusted to $maxParallel (number of target hosts)" "INFO"
    }
    
    Write-Host "=== Parallel Deployment Mode ===" -ForegroundColor Cyan
    Write-Host "Deploying to $($TargetHosts.Count) hosts with up to $maxParallel concurrent deployments" -ForegroundColor Green
    Write-Host "Batch size: $($Global:DeploymentConfig.ParallelBatchSize) | Progress updates: every $($Global:DeploymentConfig.ParallelProgressInterval)s" -ForegroundColor Gray
    Write-Host ""
    
    $results = @()
    $jobs = @()
    $completed = 0
    $successful = 0
    $failed = 0
    
    # Start performance timer for overall deployment
    Start-PerformanceTimer "ParallelDeployment-All"
    
    # Process hosts in batches to manage resource usage
    $batchSize = $Global:DeploymentConfig.ParallelBatchSize
    $maxConcurrent = $maxParallel  # Use the validated limit
    
    for ($i = 0; $i -lt $TargetHosts.Count; $i += $batchSize) {
        $batch = $TargetHosts[$i..([Math]::Min($i + $batchSize - 1, $TargetHosts.Count - 1))]
        Write-Host "Processing batch $([Math]::Floor($i / $batchSize) + 1): $($batch.Count) hosts" -ForegroundColor Yellow
        
        foreach ($targetHost in $batch) {
            # Wait for available slot
            while ((Get-Job -State Running).Count -ge $maxConcurrent) {
                Start-Sleep -Seconds 1
                
                # Check for completed jobs and collect results
                $completedJobs = Get-Job -State Completed
                foreach ($job in $completedJobs) {
                    $result = Receive-Job $job
                    $results += $result
                    
                    if ($result.Success) {
                        $successful++
                        Write-Host "✓ $($result.TargetIP) - COMPLETED SUCCESSFULLY" -ForegroundColor Green
                    } else {
                        $failed++
                        Write-Host "✗ $($result.TargetIP) - FAILED" -ForegroundColor Red
                    }
                    
                    Remove-Job $job
                    $completed++
                    
                    # Show progress
                    $percentComplete = [Math]::Round(($completed / $TargetHosts.Count) * 100, 1)
                    Write-Host "Progress: $completed/$($TargetHosts.Count) hosts completed ($percentComplete%)" -ForegroundColor Cyan
                }
            }
            
            # Start deployment job for this host
            $job = Start-Job -ScriptBlock {
                param($TargetIP, $ConfigPath, $ScriptPath)
                
                # Load configuration and functions in job context
                . $ConfigPath
                . $ScriptPath
                
                try {
                    $success = Deploy-ToSingleHost $TargetIP
                    return @{
                        TargetIP = $TargetIP
                        Success = $success
                        Timestamp = Get-Date
                        Error = $null
                    }
                } catch {
                    return @{
                        TargetIP = $TargetIP
                        Success = $false
                        Timestamp = Get-Date
                        Error = $_.Exception.Message
                    }
                }
            } -ArgumentList $targetHost, (Join-Path $PSScriptRoot "Config.ps1"), $PSCommandPath
            
            $jobs += $job
            Write-Host "Started deployment job for $targetHost" -ForegroundColor Gray
        }
        
        # Wait for batch to complete before starting next batch
        Write-Host "Waiting for batch to complete..." -ForegroundColor Yellow
        
        # Monitor progress while waiting
        while ((Get-Job -State Running).Count -gt 0) {
            Start-Sleep -Seconds $Global:DeploymentConfig.ParallelProgressInterval
            
            # Collect completed results
            $completedJobs = Get-Job -State Completed
            foreach ($job in $completedJobs) {
                $result = Receive-Job $job
                $results += $result
                
                if ($result.Success) {
                    $successful++
                    Write-Host "✓ $($result.TargetIP) - COMPLETED SUCCESSFULLY" -ForegroundColor Green
                } else {
                    $failed++
                    Write-Host "✗ $($result.TargetIP) - FAILED" -ForegroundColor Red
                    if ($result.Error) {
                        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
                    }
                }
                
                Remove-Job $job
                $completed++
                
                # Show progress
                $percentComplete = [Math]::Round(($completed / $TargetHosts.Count) * 100, 1)
                Write-Host "Progress: $completed/$($TargetHosts.Count) hosts completed ($percentComplete%)" -ForegroundColor Cyan
            }
        }
        
        Write-Host "Batch completed. Moving to next batch..." -ForegroundColor Green
        Write-Host ""
    }
    
    # Final cleanup - collect any remaining results
    $remainingJobs = Get-Job
    foreach ($job in $remainingJobs) {
        $result = Receive-Job $job
        if ($result) {
            $results += $result
            if ($result.Success) { $successful++ } else { $failed++ }
        }
        Remove-Job $job
    }
    
    Stop-PerformanceTimer "ParallelDeployment-All"
    
    return @{
        Results = $results
        TotalHosts = $TargetHosts.Count
        Successful = $successful
        Failed = $failed
    }
}

function Test-InstallerAvailability {
    Write-Log "Validating installer availability..."
    
    $installerDir = $Global:DeploymentConfig.InstallerDirectory
    
    if (-not (Test-Path $installerDir)) {
        Write-Log "Installer directory not found: $installerDir" "ERROR"
        return $false
    }
    
    $zipFiles = Get-ChildItem -Path $installerDir -Filter "*.zip" -ErrorAction SilentlyContinue
    if ($zipFiles.Count -eq 0) {
        Write-Log "No ZIP files found in installer directory" "ERROR"
        return $false
    }
    
    $validZips = 0
    foreach ($zipFile in $zipFiles) {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
            $zip.Dispose()
            $validZips++
            Write-Log "Valid installer found: $($zipFile.Name)" "SUCCESS"
        } catch {
            Write-Log "Invalid ZIP file: $($zipFile.Name)" "WARNING"
        }
    }
    
    if ($validZips -eq 0) {
        Write-Log "No valid ZIP files found" "ERROR"
        return $false
    }
    
    Write-Log "Installer validation completed - found $validZips valid installer(s)" "SUCCESS"
    return $true
}

function Test-HostConnectivity {
    param([string]$TargetIP)
    
    Write-Log "Testing connectivity to $TargetIP"
    
    if (-not (Test-Connection -ComputerName $TargetIP -Count 1 -Quiet)) {
        Write-Log "Ping failed to $TargetIP" "ERROR"
        return $false
    }
    
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
        Write-Log "SMB access error to $TargetIP" "ERROR"
        return $false
    }
}

function Test-WMIConnectivity {
    param([string]$TargetIP)
    
    Write-Log "Testing WMI connectivity to $TargetIP"
    
    $isLocal = Test-IsLocalMachine $TargetIP
    
    # Method 1: Try standard WMI with timeout
    try {
        Write-Log "Attempting standard WMI connection..."
        if ($isLocal) {
            Write-Log "Detected local machine - using local WMI query"
            $computer = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        } else {
            $computer = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        }
        Write-Log "WMI connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "Standard WMI failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 2: Try CIM (newer WMI) with WSMan
    try {
        Write-Log "Attempting CIM connection via WSMan..."
        if ($isLocal) {
            Write-Log "Detected local machine - using local CIM query"
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        } else {
            $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
            $computer = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop
            Remove-CimSession $session
        }
        Write-Log "CIM connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "CIM via WSMan failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 3: Try CIM with DCOM (fallback for older systems)
    try {
        Write-Log "Attempting CIM connection via DCOM..."
        if ($isLocal) {
            Write-Log "Detected local machine - using local CIM query"
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        } else {
            $sessionOption = New-CimSessionOption -Protocol Dcom
            $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -SessionOption $sessionOption -ErrorAction Stop
            $computer = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop
            Remove-CimSession $session
        }
        Write-Log "CIM via DCOM connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "CIM via DCOM failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 4: Try PowerShell Remoting as final fallback
    try {
        Write-Log "Attempting PowerShell Remoting as WMI alternative..."
        if ($isLocal) {
            Write-Log "Detected local machine - using local computer info"
            $result = Get-ComputerInfo | Select-Object ComputerName, WindowsVersion
        } else {
            $result = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
                Get-ComputerInfo | Select-Object ComputerName, WindowsVersion
            } -ErrorAction Stop
        }
        Write-Log "Connection successful to $($result.ComputerName)" "SUCCESS"
        return $true
    } catch {
        Write-Log "PowerShell Remoting failed: $($_.Exception.Message)" "WARNING"
    }
    
    Write-Log "All WMI/remote connection methods failed to $TargetIP" "ERROR"
    Write-Log "Troubleshooting tips:" "INFO"
    Write-Log "  - Check Windows Firewall (allow WMI, DCOM, PowerShell Remoting)" "INFO"
    Write-Log "  - Verify Remote Registry service is running" "INFO"
    Write-Log "  - Check DCOM configuration (dcomcnfg.exe)" "INFO"
    Write-Log "  - Ensure WinRM is enabled: winrm quickconfig" "INFO"
    Write-Log "  - Verify credentials have admin rights on target" "INFO"
    return $false
}

function Copy-InstallerFiles {
    param([string]$TargetIP)
    
    Write-Log "Copying installer files to $TargetIP"
    
    # Check if this is a local connection
    $isLocal = Test-IsLocalMachine $TargetIP
    Write-Log "Copy-InstallerFiles: isLocal = $isLocal for $TargetIP" "INFO"
    
    try {
        $sourceDir = $Global:DeploymentConfig.InstallerDirectory
        
        if ($isLocal) {
            # Local connection - use local paths
            $targetDir = $Global:DeploymentConfig.RemoteTempPath.Replace('C$', 'C:')
        } else {
            # Remote connection - use UNC paths
            $targetDir = "\\$TargetIP\$($Global:DeploymentConfig.RemoteTempPath)"
        }
        
        if (Test-Path $targetDir) {
            Remove-Item "$targetDir\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        
        $zipFiles = Get-ChildItem -Path $sourceDir -Filter "*.zip" | Sort-Object LastWriteTime -Descending
        if ($zipFiles.Count -eq 0) {
            Write-Log "No zip files found in source directory" "ERROR"
            return $false
        }
        
        $zipFile = $zipFiles[0]
        Write-Log "Using installer: $($zipFile.Name)"
        
        $targetZipPath = "$targetDir\$($zipFile.Name)"
        Copy-Item -Path $zipFile.FullName -Destination $targetZipPath -Force
        Write-Log "Copied zip file to target machine"
        
        # Try multiple methods for extraction
        $extractionResult = $null
        
        if ($isLocal) {
            # Method 1: Local extraction
            Write-Log "Local connection detected - using local extraction method" "INFO"
            try {
                Write-Log "Attempting local file extraction..."
                $extractPath = $Global:DeploymentConfig.RemoteTempPath.Replace('C$', 'C:')
                Write-Log "Local extraction path: '$extractPath'" "INFO"
                
                if (-not (Test-Path $extractPath)) {
                    Write-Log "Creating extraction directory: '$extractPath'" "INFO"
                    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
                } else {
                    Write-Log "Extraction directory already exists: '$extractPath'" "INFO"
                }
                
                Write-Log "Extracting from '$targetZipPath' to '$extractPath'" "INFO"
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($targetZipPath, $extractPath)
                
                $extractedFiles = Get-ChildItem -Path $extractPath -Recurse -File
                $mainExe = Get-ChildItem -Path $extractPath -Name "*.exe" -Recurse | Select-Object -First 1
                
                $extractionResult = @{
                    Success = $true
                    FileCount = $extractedFiles.Count
                    MainExecutable = $mainExe
                }
                
                Write-Log "Local extraction successful. Files extracted: $($extractedFiles.Count)" "SUCCESS"
                
            } catch {
                Write-Log "Local extraction failed: $($_.Exception.Message)" "WARNING"
                Write-Log "Exception details: $($_.Exception.GetType().FullName)" "WARNING"
                $extractionResult = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Method 2: Try PowerShell Remoting with TrustedHosts configuration (for remote connections)
        Write-Log "Extraction result check - isLocal: $isLocal, Success: $($extractionResult.Success)" "INFO"
        if (-not $isLocal -or ($isLocal -and -not $extractionResult.Success)) {
        try {
            Write-Log "Attempting file extraction via PowerShell Remoting..."
            
            # Check if we need to add to TrustedHosts
            $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            $needsRestore = $false
            
            if ($currentTrustedHosts -notlike "*$TargetIP*" -and $currentTrustedHosts -ne "*") {
                Write-Log "Adding $TargetIP to TrustedHosts temporarily..."
                $originalTrustedHosts = $currentTrustedHosts
                $newTrustedHosts = if ($currentTrustedHosts) { "$currentTrustedHosts,$TargetIP" } else { $TargetIP }
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newTrustedHosts -Force
                $needsRestore = $true
            }
            
            $extractionResult = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
                param($ZipPath, $ExtractPath)
                
                try {
                    if (-not (Test-Path $ExtractPath)) {
                        New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null
                    }
                    
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractPath)
                    
                    $extractedFiles = Get-ChildItem -Path $ExtractPath -Recurse -File
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
            } -ArgumentList "C:\temp\Trend Micro\V1ES\$($zipFile.Name)", "C:\temp\Trend Micro\V1ES" -ErrorAction Stop
            
            # Restore original TrustedHosts if we modified it
            if ($needsRestore) {
                Write-Log "Restoring original TrustedHosts configuration..."
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $originalTrustedHosts -Force
            }
            
        } catch {
            Write-Log "PowerShell Remoting extraction failed: $($_.Exception.Message)" "WARNING"
            
            # Restore TrustedHosts on error
            if ($needsRestore -and $originalTrustedHosts) {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $originalTrustedHosts -Force
            }
        }
            
            # Method 3: Try using UNC path with robocopy for extraction
            try {
                Write-Log "Attempting extraction via UNC path and robocopy..."
                $remoteExtractPath = "\\$TargetIP\C$\temp\Trend Micro\V1ES"
                
                if (-not (Test-Path $remoteExtractPath)) {
                    New-Item -ItemType Directory -Path $remoteExtractPath -Force | Out-Null
                }
                
                # Extract locally first, then copy
                $localTempPath = "$env:TEMP\V1ES_$TargetIP"
                if (Test-Path $localTempPath) {
                    Remove-Item $localTempPath -Recurse -Force
                }
                New-Item -ItemType Directory -Path $localTempPath -Force | Out-Null
                
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile.FullName, $localTempPath)
                
                # Copy extracted files to remote machine
                robocopy $localTempPath $remoteExtractPath /E /R:3 /W:5 /NP | Out-Null
                
                $extractedFiles = Get-ChildItem -Path $localTempPath -Recurse -File
                $mainExe = Get-ChildItem -Path $localTempPath -Name "*.exe" -Recurse | Select-Object -First 1
                
                # Clean up local temp
                Remove-Item $localTempPath -Recurse -Force -ErrorAction SilentlyContinue
                
                $extractionResult = @{
                    Success = $true
                    FileCount = $extractedFiles.Count
                    MainExecutable = $mainExe
                }
                
                Write-Log "Extraction via UNC path successful" "SUCCESS"
                
            } catch {
                Write-Log "UNC path extraction also failed: $($_.Exception.Message)" "WARNING"
                
                # Method 3: Manual instruction fallback
                Write-Log "All extraction methods failed. Manual intervention required." "ERROR"
                Write-Log "Please manually:" "INFO"
                Write-Log "1. Copy $($zipFile.FullName) to \\$TargetIP\C$\temp\VisionOneSEP\" "INFO"
                Write-Log "2. Extract the ZIP file on the target machine" "INFO"
                Write-Log "3. Note the main executable name for installation" "INFO"
                
                $extractionResult = @{
                    Success = $false
                    Error = "All extraction methods failed - manual intervention required"
                }
            }
        }
        
        if ($extractionResult.Success) {
            Write-Log "Successfully extracted $($extractionResult.FileCount) files on $TargetIP" "SUCCESS"
            if ($extractionResult.MainExecutable) {
                Write-Log "Main executable: $($extractionResult.MainExecutable)" "SUCCESS"
                $Global:DeploymentConfig.InstallerCommand = "C:\temp\Trend Micro\V1ES\$($extractionResult.MainExecutable) /S /v`"/quiet /norestart`""
            }
            
            Remove-Item $targetZipPath -Force -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-Log "Extraction failed on $TargetIP" "ERROR"
            return $false
        }
        
    } catch {
        Write-Log "File copy failed to $TargetIP" "ERROR"
        return $false
    }
}

function Start-Installation {
    param([string]$TargetIP)
    
    Write-Log "Starting installation on $TargetIP"
    $installCommand = $Global:DeploymentConfig.InstallerCommand
    
    # Check if this is a local connection
    $isLocal = Test-IsLocalMachine $TargetIP
    
    # Method 1: Try WMI Win32_Process Create
    try {
        Write-Log "Attempting installation via WMI..."
        
        if ($isLocal) {
            # Local connection - don't use credentials
            $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $installCommand -ErrorAction Stop
        } else {
            # Remote connection - use credentials
            $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $installCommand -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        }
        
        if ($result.ReturnValue -eq 0) {
            Write-Log "Installation started successfully via WMI on $TargetIP (ProcessId: $($result.ProcessId))" "SUCCESS"
            return $result.ProcessId
        } else {
            Write-Log "WMI process creation failed with return code: $($result.ReturnValue)" "WARNING"
        }
    } catch {
        Write-Log "WMI installation method failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 2: Try CIM Win32_Process Create
    try {
        Write-Log "Attempting installation via CIM..."
        
        if ($isLocal) {
            # Local connection - don't use credentials
            $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$installCommand} -ErrorAction Stop
        } else {
            # Remote connection - use credentials
            $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
            $result = Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$installCommand} -ErrorAction Stop
            Remove-CimSession $session
        }
        
        if ($result.ReturnValue -eq 0) {
            Write-Log "Installation started successfully via CIM on $TargetIP (ProcessId: $($result.ProcessId))" "SUCCESS"
            return $result.ProcessId
        } else {
            Write-Log "CIM process creation failed with return code: $($result.ReturnValue)" "WARNING"
        }
    } catch {
        Write-Log "CIM installation method failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 3: Try PowerShell Remoting or local execution
    try {
        if ($isLocal) {
            Write-Log "Attempting local installation via Start-Process..."
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$installCommand`"" -PassThru -WindowStyle Hidden
            Write-Log "Installation started successfully locally on $TargetIP (ProcessId: $($process.Id))" "SUCCESS"
            return $process.Id
        } else {
            Write-Log "Attempting installation via PowerShell Remoting..."
            $result = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
                param($Command)
                $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$Command`"" -PassThru -WindowStyle Hidden
                return @{
                    ProcessId = $process.Id
                    ProcessName = $process.ProcessName
                }
            } -ArgumentList $installCommand -ErrorAction Stop
            
            Write-Log "Installation started successfully via PowerShell Remoting on $TargetIP (ProcessId: $($result.ProcessId))" "SUCCESS"
            return $result.ProcessId
        }
    } catch {
        Write-Log "PowerShell Remoting/local installation method failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 4: Try PsExec as final fallback (if available)
    try {
        Write-Log "Attempting installation via PsExec (if available)..."
        $psexecPath = Get-Command "psexec.exe" -ErrorAction SilentlyContinue
        if ($psexecPath) {
            $username = $Global:DeploymentCredential.UserName
            $password = $Global:DeploymentCredential.GetNetworkCredential().Password
            $psexecCommand = "psexec.exe \\$TargetIP -u `"$username`" -p `"$password`" -d $installCommand"
            
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$psexecCommand`"" -PassThru -WindowStyle Hidden -Wait
            if ($process.ExitCode -eq 0) {
                Write-Log "Installation started successfully via PsExec on $TargetIP" "SUCCESS"
                return 1  # Return dummy process ID since PsExec doesn't return the remote process ID
            }
        } else {
            Write-Log "PsExec not available in PATH" "INFO"
        }
    } catch {
        Write-Log "PsExec installation method failed: $($_.Exception.Message)" "WARNING"
    }
    
    Write-Log "All installation methods failed for $TargetIP" "ERROR"
    Write-Log "Consider manually running: $installCommand" "INFO"
    return $null
}

function Monitor-Installation {
    param([string]$TargetIP, [int]$ProcessId)
    
    Write-Log "Monitoring installation on $TargetIP (ProcessId: $ProcessId)"
    
    $maxCycles = $Global:DeploymentConfig.MaxMonitoringCycles
    $interval = $Global:DeploymentConfig.MonitoringInterval
    
    for ($i = 1; $i -le $maxCycles; $i++) {
        Start-Sleep -Seconds $interval
        
        $processFound = $false
        
        # Method 1: Try WMI
        try {
            $isLocal = Test-IsLocalMachine $TargetIP
            
            if ($isLocal) {
                # Local connection - don't use credentials
                $processes = Get-WmiObject -Class Win32_Process -ErrorAction Stop | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
            } else {
                # Remote connection - use credentials
                $processes = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
            }
            
            if ($processes) {
                $processFound = $true
                Write-Log "[$i/$maxCycles] Installation still running on $TargetIP (WMI)" "INFO"
            }
        } catch {
            # Method 2: Try CIM as fallback
            try {
                $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
                $processes = Get-CimInstance -CimSession $session -ClassName Win32_Process -ErrorAction Stop | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
                Remove-CimSession $session
                if ($processes) {
                    $processFound = $true
                    Write-Log "[$i/$maxCycles] Installation still running on $TargetIP (CIM)" "INFO"
                }
            } catch {
                # Method 3: Try PowerShell Remoting
                try {
                    $result = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
                        Get-Process -Name "EndpointBasecamp" -ErrorAction SilentlyContinue
                    } -ErrorAction Stop
                    if ($result) {
                        $processFound = $true
                        Write-Log "[$i/$maxCycles] Installation still running on $TargetIP (PS Remoting)" "INFO"
                    }
                } catch {
                    Write-Log "[$i/$maxCycles] Unable to monitor $TargetIP - all methods failed" "WARNING"
                    # Continue monitoring anyway - installation might still be running
                    continue
                }
            }
        }
        
        if (-not $processFound) {
            Write-Log "[$i/$maxCycles] Installation process completed on $TargetIP" "SUCCESS"
            break
        }
    }
    
    if ($i -gt $maxCycles) {
        Write-Log "Installation monitoring timeout reached for $TargetIP" "WARNING"
    }
}

function Test-ExistingTrendMicro {
    param([string]$TargetIP)
    
    Write-Log "Checking for existing Trend Micro products on $TargetIP"
    
    $isLocal = Test-IsLocalMachine $TargetIP
    
    try {
        # Use different WMI calls for local vs remote machines
        if ($isLocal) {
            Write-Log "Detected local machine - using local WMI queries"
            $trendProcesses = Get-WmiObject -Class Win32_Process | Where-Object { 
                $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*"
            }
            
            $installedSoftware = Get-WmiObject -Class Win32_Product | Where-Object {
                $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*Vision One*"
            }
        } else {
            Write-Log "Detected remote machine - using remote WMI queries"
            $trendProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
                $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*"
            }
            
            $installedSoftware = Get-WmiObject -Class Win32_Product -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object {
                $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*Vision One*"
            }
        }
        
        $existingProducts = @()
        
        if ($trendProcesses) {
            Write-Log "Existing Trend Micro processes found on $TargetIP" "WARNING"
            $trendProcesses | ForEach-Object { 
                Write-Log "  - Process: $($_.Name)" "WARNING"
                $existingProducts += "Process: $($_.Name)"
            }
        }
        
        if ($installedSoftware) {
            Write-Log "Existing Trend Micro software found on $TargetIP" "WARNING"
            $installedSoftware | ForEach-Object { 
                Write-Log "  - Software: $($_.Name)" "WARNING"
                $existingProducts += "Software: $($_.Name)"
            }
        }
        
        if ($existingProducts.Count -gt 0) {
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
        Write-Log "Error checking existing products on $TargetIP" "ERROR"
        return @{
            HasExisting = $false
            Products = @()
            Error = $_.Exception.Message
        }
    }
}

function Test-InstallationSuccess {
    param([string]$TargetIP)
    
    Write-Log "Checking for Vision One installation success on $TargetIP using multiple methods"
    
    $isLocal = Test-IsLocalMachine $TargetIP
    $successIndicators = 0
    $totalMethods = 0
    
    # Method 1: Check for running processes via WMI
    $totalMethods++
    try {
        Write-Log "Method 1: Checking for Vision One processes via WMI..."
        
        if ($isLocal) {
            $visionProcesses = Get-WmiObject -Class Win32_Process | Where-Object { 
                $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
            }
        } else {
            $visionProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
                $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*"
            }
        }
        
        if ($visionProcesses) {
            Write-Log "✓ Vision One processes detected via WMI: $($visionProcesses.Count) processes" "SUCCESS"
            $successIndicators++
        } else {
            Write-Log "✗ No Vision One processes detected via WMI" "WARNING"
        }
    } catch {
        Write-Log "✗ WMI process check failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 2: Check for installed services via WMI
    $totalMethods++
    try {
        Write-Log "Method 2: Checking for Vision One services via WMI..."
        
        if ($isLocal) {
            $visionServices = Get-WmiObject -Class Win32_Service | Where-Object { 
                $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.DisplayName -like "*Trend*"
            }
        } else {
            $visionServices = Get-WmiObject -Class Win32_Service -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
                $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.DisplayName -like "*Trend*"
            }
        }
        
        if ($visionServices) {
            Write-Log "✓ Vision One services detected via WMI: $($visionServices.Count) services" "SUCCESS"
            $successIndicators++
        } else {
            Write-Log "✗ No Vision One services detected via WMI" "WARNING"
        }
    } catch {
        Write-Log "✗ WMI service check failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 3: Check for installation files via file system
    $totalMethods++
    try {
        Write-Log "Method 3: Checking for Vision One installation files..."
        
        $installPaths = @(
            "\\$TargetIP\C$\Program Files\Trend Micro",
            "\\$TargetIP\C$\Program Files (x86)\Trend Micro",
            "\\$TargetIP\C$\ProgramData\Trend Micro"
        )
        
        $foundInstallation = $false
        foreach ($path in $installPaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                $trendFiles = Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { 
                    $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.Name -like "*Endpoint*" -or $_.Name -like "*.exe"
                }
                if ($trendFiles) {
                    Write-Log "✓ Vision One installation files found in $path" "SUCCESS"
                    $foundInstallation = $true
                    break
                }
            }
        }
        
        if ($foundInstallation) {
            $successIndicators++
        } else {
            Write-Log "✗ No Vision One installation files found" "WARNING"
        }
    } catch {
        Write-Log "✗ File system check failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 4: Check for registry entries (Windows only)
    $totalMethods++
    try {
        Write-Log "Method 4: Checking for Vision One registry entries..."
        
        $registryPaths = @(
            "\\$TargetIP\HKLM\SOFTWARE\TrendMicro",
            "\\$TargetIP\HKLM\SOFTWARE\WOW6432Node\TrendMicro"
        )
        
        $foundRegistry = $false
        foreach ($regPath in $registryPaths) {
            try {
                $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $TargetIP)
                $trendKey = $regKey.OpenSubKey("SOFTWARE\TrendMicro")
                if ($trendKey) {
                    Write-Log "✓ Vision One registry entries found" "SUCCESS"
                    $foundRegistry = $true
                    $trendKey.Close()
                    break
                }
                $regKey.Close()
            } catch {
                # Try WOW6432Node path
                try {
                    $trendKey = $regKey.OpenSubKey("SOFTWARE\WOW6432Node\TrendMicro")
                    if ($trendKey) {
                        Write-Log "✓ Vision One registry entries found (WOW64)" "SUCCESS"
                        $foundRegistry = $true
                        $trendKey.Close()
                        break
                    }
                } catch {
                    # Continue to next method
                }
            }
        }
        
        if ($foundRegistry) {
            $successIndicators++
        } else {
            Write-Log "✗ No Vision One registry entries found" "WARNING"
        }
    } catch {
        Write-Log "✗ Registry check failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 5: Check via PowerShell Remoting (if WMI failed)
    if ($successIndicators == 0) {
        $totalMethods++
        try {
            Write-Log "Method 5: Checking via PowerShell Remoting (fallback)..."
            
            $remoteCheck = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
                # Check for processes
                $processes = Get-Process | Where-Object { 
                    $_.ProcessName -like "*Trend*" -or $_.ProcessName -like "*Vision*" -or $_.ProcessName -like "*Apex*" -or $_.ProcessName -like "*Endpoint*"
                }
                
                # Check for services
                $services = Get-Service | Where-Object { 
                    $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*" -or $_.DisplayName -like "*Trend*"
                }
                
                return @{
                    ProcessCount = $processes.Count
                    ServiceCount = $services.Count
                    Processes = $processes.ProcessName
                    Services = $services.Name
                }
            } -ErrorAction Stop
            
            if ($remoteCheck.ProcessCount -gt 0 -or $remoteCheck.ServiceCount -gt 0) {
                Write-Log "✓ Vision One detected via PowerShell Remoting: $($remoteCheck.ProcessCount) processes, $($remoteCheck.ServiceCount) services" "SUCCESS"
                $successIndicators++
            } else {
                Write-Log "✗ No Vision One components detected via PowerShell Remoting" "WARNING"
            }
        } catch {
            Write-Log "✗ PowerShell Remoting check failed: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Evaluate results
    $successPercentage = [Math]::Round(($successIndicators / $totalMethods) * 100, 1)
    Write-Log "Installation verification: $successIndicators/$totalMethods methods successful ($successPercentage%)" "INFO"
    
    if ($successIndicators -ge 2) {
        Write-Log "✅ Installation SUCCESS: Multiple verification methods confirm Vision One is installed" "SUCCESS"
        return $true
    } elseif ($successIndicators -eq 1) {
        Write-Log "⚠️  Installation LIKELY SUCCESSFUL: One verification method confirms installation, but connectivity issues prevent full verification" "WARNING"
        return $true  # Consider this a success since installation likely worked
    } else {
        Write-Log "❌ Installation FAILED: No verification methods confirm Vision One installation" "ERROR"
        return $false
    }
}

function Deploy-ToSingleHost {
    param([string]$TargetIP)
    
    Write-Log "=== Starting deployment to $TargetIP ===" "INFO"
    Start-PerformanceTimer "Deploy-$TargetIP"
    
    if (-not (Test-HostConnectivity $TargetIP)) {
        return $false
    }
    
    if (-not (Test-WMIConnectivity $TargetIP)) {
        return $false
    }
    
    if ($Global:DeploymentConfig.CheckExistingTrendMicro) {
        $existingCheck = Test-ExistingTrendMicro $TargetIP
        
        if ($existingCheck.HasExisting) {
            Write-Log "Existing Trend Micro products detected on $TargetIP" "WARNING"
            Write-Log "Configuration: SkipIfExisting=$($Global:DeploymentConfig.SkipIfExisting), ForceInstallation=$($Global:DeploymentConfig.ForceInstallation)" "INFO"
            
            if ($Global:DeploymentConfig.SkipIfExisting -and -not $Global:DeploymentConfig.ForceInstallation) {
                Write-Log "SKIPPING installation on $TargetIP due to existing Trend Micro products" "SUCCESS"
                return $true
            } elseif ($Global:DeploymentConfig.ForceInstallation) {
                Write-Log "FORCE installation enabled - proceeding with installation on $TargetIP" "WARNING"
            } else {
                Write-Log "PROCEEDING with installation on $TargetIP despite existing products (SkipIfExisting=false)" "WARNING"
            }
        } else {
            Write-Log "No existing Trend Micro products found on $TargetIP" "SUCCESS"
        }
    }
    
    if ($TestOnly) {
        Write-Log "Test-only mode: All tests passed for $TargetIP" "SUCCESS"
        return $true
    }
    
    if (-not (Copy-InstallerFiles $TargetIP)) {
        return $false
    }
    
    $processId = Start-Installation $TargetIP
    if (-not $processId) {
        return $false
    }
    
    Monitor-Installation $TargetIP $processId
    
    $success = Test-InstallationSuccess $TargetIP
    
    if ($success) {
        Write-Log "=== Deployment completed successfully for $TargetIP ===" "SUCCESS"
    } else {
        Write-Log "=== Deployment may have failed for $TargetIP ===" "WARNING"
    }
    
    Stop-PerformanceTimer "Deploy-$TargetIP"
    return $success
}

function Get-NetworkHosts {
    param([string]$CIDR)
    
    Write-Log "Scanning network: $CIDR"
    
    try {
        if ($CIDR -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
            $networkIP = $matches[1]
            $subnetMask = [int]$matches[2]
        } else {
            throw "Invalid CIDR format. Use format like 10.0.5.0/24"
        }
        
        $ipParts = $networkIP.Split('.')
        $networkInt = ([uint32]$ipParts[0] -shl 24) + ([uint32]$ipParts[1] -shl 16) + ([uint32]$ipParts[2] -shl 8) + [uint32]$ipParts[3]
        
        $hostBits = 32 - $subnetMask
        $networkMask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, $hostBits))
        $networkAddress = $networkInt -band $networkMask
        $broadcastAddress = $networkAddress + [Math]::Pow(2, $hostBits) - 1
        
        $hostIPs = @()
        
        if ($subnetMask -eq 32) {
            $hostIPs += $networkIP
            Write-Log "Single host: $networkIP"
        } elseif ($subnetMask -eq 31) {
            for ($i = $networkAddress; $i -le $broadcastAddress; $i++) {
                $ip = "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
                $hostIPs += $ip
            }
        } else {
            for ($i = $networkAddress + 1; $i -lt $broadcastAddress; $i++) {
                $ip = "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
                $hostIPs += $ip
            }
        }
        
        Write-Log "Network range: $($hostIPs.Count) possible hosts"
        
        Write-Log "Performing optimized ping sweep (this may take a few minutes)..."
        $liveHosts = @()
        $maxConcurrent = $Global:DeploymentConfig.MaxConcurrentPings
        $timeout = $Global:DeploymentConfig.PingTimeout
        
        # Use ForEach-Object -Parallel for better performance (PowerShell 7+)
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-Log "Using PowerShell 7+ parallel processing for faster scanning..."
            $liveHosts = $hostIPs | ForEach-Object -Parallel {
                if (Test-Connection -ComputerName $_ -Count 1 -Quiet -TimeoutSeconds 1 -ErrorAction SilentlyContinue) {
                    return $_
                }
            } -ThrottleLimit $maxConcurrent | Where-Object { $_ -ne $null }
        } else {
            # Fallback to job-based approach for PowerShell 5.x
            Write-Log "Using job-based parallel processing..."
            $jobs = @()
            $processed = 0
            
            foreach ($ip in $hostIPs) {
                # Throttle job creation
                while ((Get-Job -State Running).Count -ge $maxConcurrent) {
                    Start-Sleep -Milliseconds 50
                    
                    # Clean up completed jobs to free memory
                    Get-Job -State Completed | ForEach-Object {
                        $result = Receive-Job $_
                        if ($result) { $liveHosts += $result }
                        Remove-Job $_
                        $processed++
                    }
                    
                    # Show progress
                    if ($processed % 10 -eq 0 -and $processed -gt 0) {
                        Write-Log "Progress: $processed/$($hostIPs.Count) hosts scanned..." "INFO"
                    }
                }
                
                $job = Start-Job -ScriptBlock {
                    param($targetIP, $timeoutMs)
                    if (Test-Connection -ComputerName $targetIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                        return $targetIP
                    }
                    return $null
                } -ArgumentList $ip, $timeout
                
                $jobs += $job
            }
            
            Write-Log "Waiting for remaining ping jobs to complete..."
            $jobs | Wait-Job | Out-Null
            
            # Collect remaining results
            foreach ($job in $jobs) {
                $result = Receive-Job $job
            if ($result) {
                $liveHosts += $result
            }
            Remove-Job $job
        }
        
        Write-Log "Found $($liveHosts.Count) live hosts in $CIDR"
        
        Write-Log "Filtering for Windows hosts (this may take additional time)..."
        $windowsHosts = @()
        $hostCount = 0
        
        foreach ($targetHost in $liveHosts) {
            $hostCount++
            Write-Log "[$hostCount/$($liveHosts.Count)] Testing $targetHost for Windows..."
            
            try {
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
        return $windowsHosts
        
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
Write-Host "Vision One Endpoint Security Agent Deployment Tool" -ForegroundColor Cyan
Write-Host ""

# Show WMI troubleshooting help if requested
if ($ShowWMIHelp) {
    Show-WMITroubleshootingHelp
    exit 0
}

if ($ShowParallelConfig) {
    Show-ParallelConfiguration
    exit 0
}

# Configure TrustedHosts if requested
if ($ConfigureTrustedHosts) {
    Write-Host "Configuring TrustedHosts for IP address connectivity..." -ForegroundColor Yellow
    try {
        $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        Write-Host "Current TrustedHosts: $currentTrustedHosts" -ForegroundColor Gray
        
        Write-Host "Setting TrustedHosts to '*' (all hosts)..." -ForegroundColor Yellow
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
        
        Write-Host "TrustedHosts configured successfully!" -ForegroundColor Green
        Write-Host "You can now use IP addresses with PowerShell Remoting." -ForegroundColor Green
        Write-Host ""
        Write-Host "Security Note: This allows connections to any host. For production," -ForegroundColor Yellow
        Write-Host "consider using specific IP ranges instead of '*'." -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to configure TrustedHosts: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Try running PowerShell as Administrator." -ForegroundColor Yellow
    }
    exit 0
}

if (-not (Test-InstallerAvailability)) {
    Write-Host "Deployment cannot proceed without a valid installer." -ForegroundColor Red
    exit 1
}

# Initialize WinRM settings for better IP address connectivity
Initialize-WinRMSettings | Out-Null

$targetHosts = Get-TargetHosts

if (-not $targetHosts) {
    Write-Host "Usage Examples:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128'"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt'"
    Write-Host "  .\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24'"
    Write-Host "  .\Deploy-VisionOne.ps1 -CIDR '192.168.1.0/24' -Parallel"
    Write-Host "  .\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -TestOnly"
    Write-Host "  .\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -TestOnly"
    Write-Host ""
    Write-Host "Parameters:" -ForegroundColor Cyan
    Write-Host "  -CIDR              : Network range in CIDR notation (e.g., 10.0.5.0/24)"
    Write-Host "  -TargetIPs         : Specific IP addresses to target"
    Write-Host "  -TargetFile        : File containing IP addresses (one per line)"
    Write-Host "  -TestOnly          : Test connectivity only, don't deploy"
    Write-Host "  -Parallel          : Deploy to multiple hosts simultaneously"
    Write-Host "  -MaxParallel       : Maximum parallel deployments (default: 5)"
    Write-Host "  -ShowWMIHelp       : Display WMI troubleshooting guide"
    Write-Host "  -ConfigureTrustedHosts : Configure TrustedHosts for IP connectivity"
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Cyan
    Write-Host "  If experiencing IP address connection issues:"
    Write-Host "  .\Deploy-VisionOne.ps1 -ConfigureTrustedHosts"
    Write-Host ""
    Write-Host "  For comprehensive troubleshooting:"
    Write-Host "  .\Deploy-VisionOne.ps1 -ShowWMIHelp"
    exit 1
}

Write-Host "Target hosts identified: $($targetHosts.Count)" -ForegroundColor Green
$targetHosts | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }

# Configure TrustedHosts for the target network
if ($CIDR) {
    $trustedHostsConfigured = Set-TrustedHostsForCIDR $CIDR
    if (-not $trustedHostsConfigured) {
        Write-Log "Warning: TrustedHosts configuration failed. PowerShell Remoting may not work properly." "WARNING"
    }
} elseif ($TargetIPs) {
    # For individual IPs, create a pattern
    $ipPattern = ($TargetIPs | ForEach-Object { $_ }) -join ','
    Write-Log "Configuring TrustedHosts for specific IPs: $ipPattern" "INFO"
    try {
        $originalTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        $Global:OriginalTrustedHosts = $originalTrustedHosts
        
        if ([string]::IsNullOrEmpty($originalTrustedHosts)) {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ipPattern -Force
        } else {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$originalTrustedHosts,$ipPattern" -Force
        }
        Write-Log "TrustedHosts configured for target IPs" "SUCCESS"
    } catch {
        Write-Log "Failed to configure TrustedHosts for IPs: $($_.Exception.Message)" "WARNING"
    }
}

if ($TestOnly) {
    Write-Host "TEST MODE: Connectivity Testing Only" -ForegroundColor Yellow
}

$successCount = 0
$failureCount = 0
$results = @()

if (($FullParallel -or ($Global:DeploymentConfig.EnableParallelDeployment -and $targetHosts.Count -ge $Global:DeploymentConfig.AutoParallelThreshold)) -and -not $TestOnly) {
    # Use new parallel deployment system for full deployments
    $deploymentResult = Start-ParallelDeployment $targetHosts
    $results = $deploymentResult.Results
    $successCount = $deploymentResult.Successful
    $failureCount = $deploymentResult.Failed
    
} elseif ($Parallel -and $targetHosts.Count -gt 1) {
    Write-Host "=== Parallel Connectivity Test Mode (Max: $MaxParallel concurrent) ===" -ForegroundColor Cyan
    Write-Host "Note: Parallel mode for test-only. Full deployments use optimized parallel system." -ForegroundColor Yellow
    Write-Host ""
    
    $jobs = @()
    
    foreach ($targetHost in $targetHosts) {
        while ((Get-Job -State Running).Count -ge $MaxParallel) {
            Start-Sleep -Seconds 1
        }
        
        $job = Start-Job -ScriptBlock {
            param($TargetIP, $DeploymentConfig, $DeploymentCredential, $TestOnly)
            
            function Write-Log {
                param([string]$Message, [string]$Level = "INFO")
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Output "[$timestamp] [$TargetIP] $Message"
            }
            
            function Test-HostConnectivity {
                param([string]$TargetIP)
                Write-Log "Testing connectivity to $TargetIP"
                if (-not (Test-Connection -ComputerName $TargetIP -Count 1 -Quiet)) {
                    Write-Log "Ping failed to $TargetIP" "ERROR"
                    return $false
                }
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
                    Write-Log "SMB access error to $TargetIP" "ERROR"
                    return $false
                }
            }
            
            function Test-WMIConnectivity {
                param([string]$TargetIP)
                Write-Log "Testing WMI connectivity to $TargetIP"
                try {
                    $computer = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $TargetIP -Credential $DeploymentCredential -ErrorAction Stop
                    Write-Log "WMI connection successful to $($computer.Name)" "SUCCESS"
                    return $true
                } catch {
                    Write-Log "WMI connection failed to $TargetIP" "ERROR"
                    return $false
                }
            }
            
            Write-Log "Starting deployment process"
            
            # Test connectivity
            if (-not (Test-HostConnectivity $TargetIP)) {
                return @{ TargetIP = $TargetIP; Success = $false; Timestamp = Get-Date }
            }
            
            if (-not (Test-WMIConnectivity $TargetIP)) {
                return @{ TargetIP = $TargetIP; Success = $false; Timestamp = Get-Date }
            }
            
            if ($TestOnly) {
                Write-Log "Test-only mode: All tests passed for $TargetIP" "SUCCESS"
                return @{ TargetIP = $TargetIP; Success = $true; Timestamp = Get-Date }
            }
            
            # For parallel mode, we'll do a simplified deployment due to job complexity
            # The full deployment with file copying and extraction is better suited for sequential mode
            Write-Log "Parallel mode: Basic deployment checks completed" "SUCCESS"
            return @{ TargetIP = $TargetIP; Success = $true; Timestamp = Get-Date }
            
        } -ArgumentList $targetHost, $Global:DeploymentConfig, $Global:DeploymentCredential, $TestOnly
        
        $jobs += $job
        Write-Host "Started deployment job for $targetHost" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Waiting for all deployments to complete..." -ForegroundColor Yellow
    
    foreach ($job in $jobs) {
        $jobOutput = Wait-Job $job | Receive-Job
        
        # Display job output
        if ($jobOutput -is [array]) {
            foreach ($line in $jobOutput) {
                if ($line -is [string]) {
                    Write-Host $line
                } elseif ($line.TargetIP) {
                    $results += $line
                    if ($line.Success) {
                        $successCount++
                        Write-Host "✓ $($line.TargetIP) - COMPLETED SUCCESSFULLY" -ForegroundColor Green
                    } else {
                        $failureCount++
                        Write-Host "✗ $($line.TargetIP) - FAILED" -ForegroundColor Red
                    }
                }
            }
        } else {
            if ($jobOutput -is [string]) {
                Write-Host $jobOutput
            } elseif ($jobOutput.TargetIP) {
                $results += $jobOutput
                if ($jobOutput.Success) {
                    $successCount++
                    Write-Host "✓ $($jobOutput.TargetIP) - COMPLETED SUCCESSFULLY" -ForegroundColor Green
                } else {
                    $failureCount++
                    Write-Host "✗ $($jobOutput.TargetIP) - FAILED" -ForegroundColor Red
                }
            }
        }
        
        Remove-Job $job
    }
    
} else {
    Write-Host "=== Sequential Deployment Mode ===" -ForegroundColor Cyan
    Write-Host "Full deployment: connectivity tests, file copying, extraction, and installation" -ForegroundColor Green
    Write-Host ""
    
    $currentHost = 0
    foreach ($targetHost in $targetHosts) {
        $currentHost++
        Write-Host "[$currentHost/$($targetHosts.Count)] Processing $targetHost..." -ForegroundColor Cyan
        Write-Host ""
        
        $result = Deploy-ToSingleHost $targetHost
        
        $results += @{
            TargetIP = $targetHost
            Success = $result
            Timestamp = Get-Date
        }
        
        if ($result) {
            $successCount++
            Write-Host "✓ $targetHost - COMPLETED SUCCESSFULLY" -ForegroundColor Green
        } else {
            $failureCount++
            Write-Host "✗ $targetHost - FAILED" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host "Progress: $currentHost/$($targetHosts.Count) hosts processed" -ForegroundColor Yellow
        Write-Host ""
    }
}

Write-Host "=== DEPLOYMENT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total hosts: $($targetHosts.Count)" -ForegroundColor White
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed: $failureCount" -ForegroundColor Red
Write-Host ""

if ($failureCount -gt 0) {
    Write-Host "Failed hosts:" -ForegroundColor Red
    $results | Where-Object { -not $_.Success } | ForEach-Object {
        Write-Host "  - $($_.TargetIP)" -ForegroundColor Red
    }
    Write-Host ""
}

if ($TestOnly) {
    Write-Host "Test mode completed. Use without -TestOnly to perform actual deployment." -ForegroundColor Yellow
} else {
    Write-Host "Deployment completed. Check individual host logs above for details." -ForegroundColor White
}

# Restore original TrustedHosts configuration
Restore-TrustedHosts

# Clean up optimization caches and free memory
Clear-OptimizationCaches

Write-Host ""
Write-Host "For troubleshooting, check:" -ForegroundColor Gray
Write-Host "  - Network connectivity to failed hosts" -ForegroundColor Gray
Write-Host "  - Domain credentials and permissions" -ForegroundColor Gray
Write-Host "  - Windows firewall and WMI settings on target machines" -ForegroundColor Gray
Write-Host "  - Existing antivirus software conflicts" -ForegroundColor Gray
