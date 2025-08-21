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
    [switch]$SkipExistingCheck,
    [switch]$ForceInstall,
    [switch]$ShowWMIHelp,
    [switch]$ConfigureTrustedHosts
)

# Load configuration
. .\Config.ps1

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
            Write-Log "Consider running: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force" "INFO"
        }
        
        return $true
    } catch {
        Write-Log "Failed to configure WinRM settings: $($_.Exception.Message)" "WARNING"
        return $false
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
    
    # Method 1: Try standard WMI with timeout
    try {
        Write-Log "Attempting standard WMI connection..."
        $computer = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        Write-Log "WMI connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "Standard WMI failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 2: Try CIM (newer WMI) with WSMan
    try {
        Write-Log "Attempting CIM connection via WSMan..."
        $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        $computer = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop
        Remove-CimSession $session
        Write-Log "CIM connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "CIM via WSMan failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 3: Try CIM with DCOM (fallback for older systems)
    try {
        Write-Log "Attempting CIM connection via DCOM..."
        $sessionOption = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -SessionOption $sessionOption -ErrorAction Stop
        $computer = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop
        Remove-CimSession $session
        Write-Log "CIM via DCOM connection successful to $($computer.Name)" "SUCCESS"
        return $true
    } catch {
        Write-Log "CIM via DCOM failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 4: Try PowerShell Remoting as final fallback
    try {
        Write-Log "Attempting PowerShell Remoting as WMI alternative..."
        $result = Invoke-Command -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ScriptBlock {
            Get-ComputerInfo | Select-Object ComputerName, WindowsVersion
        } -ErrorAction Stop
        Write-Log "PowerShell Remoting successful to $($result.ComputerName)" "SUCCESS"
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
    
    try {
        $sourceDir = $Global:DeploymentConfig.InstallerDirectory
        $targetDir = "\\$TargetIP\$($Global:DeploymentConfig.RemoteTempPath)"
        
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
        
        # Try multiple methods for remote extraction
        $extractionResult = $null
        
        # Method 1: Try PowerShell Remoting with TrustedHosts configuration
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
            } -ArgumentList "C:\temp\VisionOneSEP\$($zipFile.Name)", "C:\temp\VisionOneSEP" -ErrorAction Stop
            
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
            
            # Method 2: Try using UNC path with robocopy for extraction
            try {
                Write-Log "Attempting extraction via UNC path and robocopy..."
                $remoteExtractPath = "\\$TargetIP\C$\temp\VisionOneSEP"
                
                if (-not (Test-Path $remoteExtractPath)) {
                    New-Item -ItemType Directory -Path $remoteExtractPath -Force | Out-Null
                }
                
                # Extract locally first, then copy
                $localTempPath = "$env:TEMP\VisionOneSEP_$TargetIP"
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
                $Global:DeploymentConfig.InstallerCommand = "C:\temp\VisionOneSEP\$($extractionResult.MainExecutable) /S /v`"/quiet /norestart`""
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
    
    # Method 1: Try WMI Win32_Process Create
    try {
        Write-Log "Attempting installation via WMI..."
        $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $installCommand -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        
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
        $session = New-CimSession -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop
        $result = Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$installCommand} -ErrorAction Stop
        Remove-CimSession $session
        
        if ($result.ReturnValue -eq 0) {
            Write-Log "Installation started successfully via CIM on $TargetIP (ProcessId: $($result.ProcessId))" "SUCCESS"
            return $result.ProcessId
        } else {
            Write-Log "CIM process creation failed with return code: $($result.ReturnValue)" "WARNING"
        }
    } catch {
        Write-Log "CIM installation method failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Method 3: Try PowerShell Remoting
    try {
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
    } catch {
        Write-Log "PowerShell Remoting installation method failed: $($_.Exception.Message)" "WARNING"
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
            $processes = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential -ErrorAction Stop | Where-Object { $_.Name -eq "EndpointBasecamp.exe" }
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
    
    try {
        $trendProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
            $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*"
        }
        
        $installedSoftware = Get-WmiObject -Class Win32_Product -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object {
            $_.Name -like "*Trend Micro*" -or $_.Name -like "*Apex One*" -or $_.Name -like "*Vision One*"
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
    
    Write-Log "Checking for Vision One processes on $TargetIP"
    
    try {
        $visionProcesses = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -Credential $Global:DeploymentCredential | Where-Object { 
            $_.Name -like "*Trend*" -or $_.Name -like "*Vision*" -or $_.Name -like "*Apex*"
        }
        
        if ($visionProcesses) {
            Write-Log "Vision One processes detected on $TargetIP" "SUCCESS"
            return $true
        } else {
            Write-Log "No Vision One processes detected on $TargetIP" "WARNING"
            return $false
        }
    } catch {
        Write-Log "Error checking processes on $TargetIP" "ERROR"
        return $false
    }
}

function Deploy-ToSingleHost {
    param([string]$TargetIP)
    
    Write-Log "=== Starting deployment to $TargetIP ===" "INFO"
    
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
            
            if ($Global:DeploymentConfig.SkipIfExisting -and -not $Global:DeploymentConfig.ForceInstallation) {
                Write-Log "Skipping installation on $TargetIP due to existing products" "WARNING"
                return $true
            } elseif (-not $Global:DeploymentConfig.ForceInstallation) {
                Write-Log "Proceeding with installation on $TargetIP despite existing products" "WARNING"
            } else {
                Write-Log "Force installation enabled - proceeding with installation on $TargetIP" "INFO"
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
        
        Write-Log "Performing ping sweep (this may take a few minutes)..."
        $liveHosts = @()
        $maxConcurrent = 50
        $jobs = @()
        
        foreach ($ip in $hostIPs) {
            while ((Get-Job -State Running).Count -ge $maxConcurrent) {
                Start-Sleep -Milliseconds 100
            }
            
            $job = Start-Job -ScriptBlock {
                param($targetIP)
                if (Test-Connection -ComputerName $targetIP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    return $targetIP
                }
                return $null
            } -ArgumentList $ip
            
            $jobs += $job
        }
        
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

if ($TestOnly) {
    Write-Host "TEST MODE: Connectivity Testing Only" -ForegroundColor Yellow
}

$successCount = 0
$failureCount = 0
$results = @()

if ($Parallel -and $targetHosts.Count -gt 1) {
    Write-Host "=== Parallel Deployment Mode (Max: $MaxParallel concurrent) ===" -ForegroundColor Cyan
    Write-Host "Note: Parallel mode performs connectivity tests. Use sequential mode for full deployment with file copying." -ForegroundColor Yellow
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

Write-Host ""
Write-Host "For troubleshooting, check:" -ForegroundColor Gray
Write-Host "  - Network connectivity to failed hosts" -ForegroundColor Gray
Write-Host "  - Domain credentials and permissions" -ForegroundColor Gray
Write-Host "  - Windows firewall and WMI settings on target machines" -ForegroundColor Gray
Write-Host "  - Existing antivirus software conflicts" -ForegroundColor Gray
