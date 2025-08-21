# Vision One Endpoint Security Agent Deployment Configuration
# Edit these settings for your environment

# Deployment Configuration - No user configuration required
$Global:DeploymentConfig = @{
    
    # Paths
    InstallerDirectory = ".\installer"
    RemoteTempPath = "C$\temp\Trend Micro\V1ES"
    
    # Installation Settings
    InstallationTimeout = 1200  # 20 minutes (doubled from 10)
    MonitoringInterval = 30     # 30 seconds (keeping same for responsiveness)
    MaxMonitoringCycles = 12    # 6 minutes total (doubled from 3)
    
    # Pre-installation Checks
    CheckExistingTrendMicro = $true    # Check for existing Trend Micro products
    SkipIfExisting = $true             # Set to $true to skip installation if existing products found
    ForceInstallation = $false         # Set to $true to install even if existing products found
    
    # Network Scanning
    MaxConcurrentPings = 50            # Maximum concurrent ping operations during network scan
    PingTimeout = 1000                 # Ping timeout in milliseconds
    ScanOnlyWindowsHosts = $false      # Set to $true to filter for Windows hosts only (slower)
    
    # Performance Optimizations
    EnablePerformanceTimers = $true    # Enable performance timing for operations
    EnableCaching = $true              # Enable caching for local detection and WMI sessions
    UseOptimizedFileOps = $true        # Use robocopy for better file copy performance
    CleanupInterval = 10               # Clean up completed jobs every N operations
    
    # Parallel Deployment Settings
    EnableParallelDeployment = $true   # Enable parallel deployment for multiple hosts
    MaxParallelDeployments = 5         # Maximum concurrent deployments (1-20 recommended)
    ParallelBatchSize = 10             # Process hosts in batches of this size
    ParallelProgressInterval = 5       # Update progress every N seconds
    AutoParallelThreshold = 4          # Automatically use parallel mode for N+ hosts
    
    # Parallel Deployment Limits by System Resources
    # Adjust based on your system capabilities:
    # - Low-end systems: 2-3 concurrent deployments
    # - Mid-range systems: 5-8 concurrent deployments  
    # - High-end systems: 10-15 concurrent deployments
    # - Server-class systems: 15-20 concurrent deployments
    
    # Installer Command
    InstallerCommand = "C:\temp\Trend Micro\V1ES\EndpointBasecamp.exe /S /v`"/quiet /norestart`""
}

# No credential functions needed - credentials are prompted directly in the main script

Write-Host "Configuration loaded for Vision One Endpoint Security Agent Deployment" -ForegroundColor Green