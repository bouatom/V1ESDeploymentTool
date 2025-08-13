# VisionOne SEP Deployment Configuration
# Edit these settings for your environment

# Credentials - EDIT THESE FOR YOUR ENVIRONMENT
$Global:DeploymentConfig = @{
    Username = "DOMAIN\username"        # Change to your domain\username
    Password = "your_password_here"     # Change to your password
    Domain = "your.domain.com"          # Change to your domain
    
    # Paths
    InstallerDirectory = ".\installer"
    RemoteTempPath = "C$\temp\VisionOneSEP"
    
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
    InstallerCommand = "C:\temp\VisionOneSEP\EndpointBasecamp.exe /S /v`"/quiet /norestart`""
}

# Function to get credentials
function Get-DeploymentCredentials {
    $pass = ConvertTo-SecureString $Global:DeploymentConfig.Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Global:DeploymentConfig.Username, $pass)
}

Write-Host "Configuration loaded for VisionOne SEP Deployment" -ForegroundColor Green