# Vision One Endpoint Security Agent Deployment Configuration
# Edit these settings for your environment

# Deployment Configuration - No user configuration required
$Global:DeploymentConfig = @{
    
    # Paths
    InstallerDirectory = ".\installer"
    RemoteTempPath = "C$\temp\Trend Micro\V1ES"
    
    # Installation Settings
    InstallationTimeout = 600  # 10 minutes
    MonitoringInterval = 30    # 30 seconds
    MaxMonitoringCycles = 6    # 3 minutes total
    
    # Pre-installation Checks
    CheckExistingTrendMicro = $true    # Check for existing Trend Micro products
    SkipIfExisting = $false            # Set to $true to skip installation if existing products found
    ForceInstallation = $false         # Set to $true to install even if existing products found
    
    # Network Scanning
    MaxConcurrentPings = 50            # Maximum concurrent ping operations during network scan
    PingTimeout = 1000                 # Ping timeout in milliseconds
    ScanOnlyWindowsHosts = $false      # Set to $true to filter for Windows hosts only (slower)
    
    # Installer Command
    InstallerCommand = "C:\temp\Trend Micro\V1ES\EndpointBasecamp.exe /S /v`"/quiet /norestart`""
}

# No credential functions needed - credentials are prompted directly in the main script

Write-Host "Configuration loaded for Vision One Endpoint Security Agent Deployment" -ForegroundColor Green