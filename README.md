# Vision One Endpoint Security Agent Deployment Tool - PowerShell Edition

A simple, reliable PowerShell-based deployment tool for Trend Micro Vision One Endpoint Security Agent across Windows networks.

## 🚀 **Key Features**

- **Pure PowerShell Solution**: No Python dependencies or complexity
- **Proven Methods**: Uses native Windows authentication and WMI
- **Multiple Deployment Options**: Single host, multiple hosts, or file-based targets
- **Parallel Deployment**: Deploy to multiple machines simultaneously
- **Real-time Monitoring**: Track installation progress and verify success
- **Simple Configuration**: Easy-to-edit PowerShell configuration file
- **Comprehensive Logging**: Clear status messages and error reporting

## 📁 **Files Overview**

### **Main Scripts**
- `Deploy-VisionOne.ps1` - Main deployment script with all features (no configuration required)
- `Deploy-Simple.ps1` - Simple single-host deployment
- `Config.ps1` - Internal configuration file (no user editing required)

### **Supporting Files**
- `hosts.txt` - Target host list (one IP per line)
- `Deploy-Multiple.bat` - Batch file for multiple deployments
- `config.json` - Legacy configuration (not used by PowerShell scripts)

### **Installer**
- `installer/` - Directory containing Vision One Endpoint Security Agent installer files

## � ***Prerequisites**

### **Required Permissions**
The deployment requires an account with **administrator permissions** on the target machines. This can be:
- A **domain account** that is a member of the local Administrators group on target machines
- A **local administrator account** that exists on all target machines
- An account with **local admin rights** granted through Group Policy or direct assignment

### **Network Requirements**
- Administrative shares enabled on target machines (`C$`, `ADMIN$`)
- WMI service running on target machines
- Windows Firewall configured to allow WMI and file sharing
- Network connectivity between deployment machine and targets

## 🔧 **Quick Start**

### **1. No Configuration Required**
The script prompts for all required information at runtime:
- **Domain name** (e.g., CONTOSO, your.domain.com)
- **Username and password** for an account with administrator permissions on target machines

**No editing of configuration files is required!**

### **2. Deploy to Single Host**
```powershell
# Simple deployment
.\Deploy-Simple.ps1 -TargetIP 10.0.5.127

# Full deployment with monitoring
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'
```

### **3. Deploy to Multiple Hosts**
```powershell
# Multiple IPs
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128','10.0.5.129'

# From file
.\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt'

# Parallel deployment
.\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt' -Parallel -MaxParallel 3
```

### **4. Deploy to Entire VLAN/Network**
```powershell
# Scan and deploy to entire subnet
.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24'

# Scan subnet in parallel (faster for large networks)
.\Deploy-VisionOne.ps1 -CIDR '192.168.1.0/24' -Parallel -MaxParallel 5

# Test network scan without deploying
.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -TestOnly
```

### **5. Test Connectivity Only**
```powershell
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -TestOnly
.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -TestOnly
```

### **6. Network Discovery**
```powershell
# Scan network and save discovered hosts to file
.\Scan-Network.ps1 -CIDR '10.0.5.0/24' -SaveToFile

# Scan for Windows hosts only
.\Scan-Network.ps1 -CIDR '10.0.5.0/24' -WindowsOnly -SaveToFile

# Then deploy using discovered hosts
.\Deploy-VisionOne.ps1 -TargetFile 'discovered_hosts.txt'
```

## 📋 **Usage Examples**

### **Basic Deployment**
```powershell
# Deploy to a single machine
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'
```

### **Multiple Machines**
```powershell
# Deploy to multiple machines sequentially
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128','10.0.5.129'

# Deploy to multiple machines in parallel (faster)
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128','10.0.5.129' -Parallel -MaxParallel 3
```

### **File-Based Deployment**
```powershell
# Create hosts.txt with target IPs (one per line)
# Then deploy to all hosts in the file
.\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt' -Parallel
```

### **Test Mode**
```powershell
# Test connectivity without deploying
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -TestOnly
```

## 🔧 **Advanced Configuration (Optional)**

The script uses sensible defaults, but you can customize settings in `Config.ps1` if needed:

```powershell
$Global:DeploymentConfig = @{
    # Paths
    InstallerDirectory = ".\installer"
    RemoteTempPath = "C$\temp\Trend Micro\V1ES"
    
    # Timeouts
    InstallationTimeout = 600  # 10 minutes
    MonitoringInterval = 30    # 30 seconds
    MaxMonitoringCycles = 6    # 3 minutes total monitoring
    
    # Network Scanning
    MaxConcurrentPings = 50    # Concurrent ping operations
    ScanOnlyWindowsHosts = $false  # Filter for Windows hosts only
}
```

**Note:** No user credentials or domain information is stored in configuration files.

## 📊 **What the Script Does**

1. **Tests Connectivity**: Ping and SMB access to target machines
2. **Tests WMI**: Verifies WMI authentication works
3. **Copies Files**: Copies entire installer directory to target
4. **Starts Installation**: Uses WMI to execute the installer
5. **Monitors Progress**: Tracks installation process
6. **Verifies Success**: Checks for Vision One processes

## 🎯 **Deployment Process**

```
Target Machine: 10.0.5.127
├── Test Connectivity (Ping + SMB)
├── Test WMI Authentication  
├── Copy Installer Files
│   ├── Create C:\temp\Trend Micro\V1ES\
│   ├── Copy EndpointBasecamp.exe
│   ├── Copy config.json
│   └── Copy packages\ directory
├── Start Installation via WMI
├── Monitor Installation Progress
└── Verify Vision One Processes
```

## 🔍 **Troubleshooting**

### **Common Issues**

1. **"Access Denied" Errors**
   - Ensure you're using an account with administrator permissions on target machines
   - Verify the account has local admin rights or is part of the local Administrators group
   - Verify target machine allows admin shares

2. **WMI Connection Failed**
   - Run `configure_target_machine.bat` on target machines
   - Check Windows Firewall settings
   - Verify WinRM is enabled

3. **File Copy Failed**
   - Check network connectivity
   - Verify admin share access (`\\target\C$`)
   - Ensure sufficient disk space

### **Test Commands**
```powershell
# Test basic connectivity
Test-Connection -ComputerName 10.0.5.127 -Count 1

# Test admin share access
Test-Path "\\10.0.5.127\C$"

# Test WMI manually
Get-WmiObject -Class Win32_ComputerSystem -ComputerName 10.0.5.127 -Credential $cred
```

## 📁 **File Structure**
```
Deployment/
├── Deploy-VisionOne.ps1      # Main deployment script
├── Deploy-Simple.ps1         # Simple single-host deployment  
├── Config.ps1               # Configuration file
├── hosts.txt                # Target host list
├── installer/               # Vision One Endpoint Security Agent installer files
│   ├── EndpointBasecamp.exe
│   ├── config.json
│   └── packages/
└── README-PowerShell.md     # This file
```

## 🎉 **Benefits of PowerShell-Only Approach**

- ✅ **No Python Dependencies**: Works on any Windows machine
- ✅ **Native Authentication**: Uses Windows integrated security
- ✅ **Proven Methods**: Same commands that work manually
- ✅ **Simple Troubleshooting**: Clear error messages
- ✅ **Easy Customization**: Edit PowerShell scripts directly
- ✅ **Reliable**: No subprocess authentication issues

## 🔒 **Security Features**

### **Secure Credential Handling**
- **No Storage**: Credentials are never stored anywhere - not in files, cache, or memory after use
- **Direct Prompting**: Script prompts for credentials only when needed and discards them after completion
- **Session-Only**: Credentials exist only in memory during script execution
- **Zero Persistence**: No credential files, cache, or temporary storage created

### **How It Works**
When you run the script, you'll see:
```
=== Vision One Endpoint Security Agent Deployment ===

Please enter credentials for an account with administrator permissions on target machines
Format: DOMAIN\username (e.g., CONTOSO\admin)

[Windows credential prompt appears]

If you enter just a username (without domain):
Username should be in DOMAIN\username format

Enter domain name (e.g., CONTOSO, your.domain.com): CONTOSO
✓ Credentials loaded for user: CONTOSO\admin
```

### **Security Benefits**
- **Maximum Security**: No credential artifacts left on disk
- **Simple & Clean**: No cache management or cleanup required
- **Audit Friendly**: No stored credentials to secure or rotate
- **Zero Trust**: Credentials are prompted fresh for each deployment

### **Additional Security Notes**
- The script uses WMI for remote execution - ensure this aligns with your security policies
- All operations use your provided credentials (requires administrator permissions on target machines)
- Consider running from a secure administrative workstation
- Credentials are automatically cleared from memory when script completes

## 📞 **Support**

For issues or questions:
1. Check the troubleshooting section above
2. Verify your configuration in `Config.ps1`
3. Test connectivity manually using the provided commands
4. Review the script output for specific error messages