# Vision One Endpoint Security Agent Deployment Tool - Complete File Documentation

## 🚀 **Main Deployment Scripts**

### **`Deploy-VisionOne.ps1`** - Primary Deployment Engine
**Purpose**: Full-featured deployment script with enterprise capabilities
**Features**:
- Single host, multiple hosts, CIDR network scanning
- Parallel deployment with configurable concurrency
- Existing Trend Micro product detection and conflict handling
- Comprehensive pre-deployment checks (connectivity, WMI, SMB)
- Real-time monitoring and progress tracking
- Detailed audit logging and error reporting
**Usage**: `.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'` or `.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24'`

### **`Deploy-Simple.ps1`** - Quick Single-Host Deployment
**Purpose**: Simplified deployment for single machines with minimal configuration
**Features**:
- Single target deployment with basic checks
- Existing product detection with warnings
- Step-by-step progress display with colored output
- Installation monitoring and verification
**Usage**: `.\Deploy-Simple.ps1 -TargetIP 10.0.5.127`

### **`Scan-Network.ps1`** - Network Discovery Tool
**Purpose**: Discover and identify Windows hosts in network ranges
**Features**:
- CIDR network scanning with concurrent ping operations
- Windows host filtering (tests admin share access)
- Save discovered hosts to file for batch deployment
- Progress tracking for large network scans
- Configurable concurrency and timeouts
**Usage**: `.\Scan-Network.ps1 -CIDR '10.0.5.0/24' -WindowsOnly -SaveToFile`

## ⚙️ **Configuration Files**

### **`Config.ps1`** - Internal Configuration
**Purpose**: Internal configuration file for deployment settings (no user editing required)
**Contains**:
- **Paths**: Installer directory, remote temp paths (`C$\temp\Trend Micro\V1ES`)
- **Timeouts**: Installation, monitoring, network scan timeouts
- **Security Settings**: Existing product checks, force installation flags
- **Network Options**: Concurrent operations, Windows-only filtering
**Note**: No credentials stored - all authentication is prompted at runtime

### **`hosts.txt`** - Target Host List
**Purpose**: Predefined list of target IP addresses for batch deployment
**Format**: One IP per line, supports comments with #
**Usage**: Used with `-TargetFile` parameter for batch deployments
**Example Content**:
```
# Production servers
10.0.5.127
10.0.5.128
# 10.0.5.129  # Commented out
```

## 🔧 **Target Machine Setup Tools**

### **`configure_target_machine.bat`** - Target Machine Preparation
**Purpose**: Configure target machines to accept remote deployment
**Actions**:
- Enables WinRM service and configures authentication
- Sets WinRM service settings (AllowUnencrypted, Basic auth)
- Starts WMI service and sets to automatic startup
- Enables PowerShell remoting with network profile skip
- Configures DCOM settings for WMI access
- Disables UAC remote restrictions for admin accounts
**Usage**: Copy to target machine and run as Administrator

### **`check_wmi_services.bat`** - Service Verification
**Purpose**: Verify WMI and related services are running on target machines
**Checks**:
- Windows Management Instrumentation service status
- Remote Procedure Call (RPC) services
- RPC Endpoint Mapper service
- DCOM Server Process Launcher
- Local WMI functionality test
- Windows Firewall status
**Usage**: Run on target machine to verify configuration

### **`Test-Prerequisites.ps1`** - Deployment Readiness Test
**Purpose**: Test deployment prerequisites and connectivity from deployment machine
**Tests**:
- Network connectivity to targets
- WMI authentication and access
- PowerShell remoting capabilities
- Admin share access verification
**Usage**: `.\Test-Prerequisites.ps1` (run from deployment machine)

## 🔄 **Batch Deployment Tools**

### **`Deploy-Multiple.bat`** - Batch Deployment Wrapper
**Purpose**: Simple batch file for deploying to multiple predefined machines
**Features**:
- Sequential deployment to multiple IPs
- Easy to edit for different target lists
- Pause between deployments for review
- Can be customized for specific environments
**Usage**: Edit IP addresses in file, then run `Deploy-Multiple.bat`

## 📦 **Installer Components**

### **`installer/`** - Vision One Endpoint Security Agent Installer Directory
**Purpose**: Contains the Vision One Endpoint Security Agent installer ZIP file

#### **IMPORTANT: Unique Installer Requirement**
**Each user must obtain their own personalized Vision One Endpoint Security Agent installer:**
- Download your unique installer ZIP from the Trend Micro Vision One portal
- Each organization/user has a unique installer that cannot be shared
- Place the entire ZIP file in the `installer/` directory
- **Do not extract the ZIP file** - scripts handle extraction automatically

#### **How the Installer Works:**
1. **Detection**: Scripts automatically find any `.zip` file in the installer directory
2. **Smart Selection**: If multiple ZIP files exist (e.g., duplicates with `(1)`, `(2)` suffixes), scripts prefer the original filename or most recent file
3. **Transfer**: The selected ZIP file is copied to the target machine's temp directory
4. **Remote Extraction**: ZIP is extracted on the target machine using .NET compression
5. **Installation**: The extracted executable is run with silent installation parameters
6. **Cleanup**: Temporary files are removed after installation

#### **Handling Duplicate Downloads:**
- If you have multiple ZIP files (e.g., `installer.zip`, `installer (1).zip`, `installer (2).zip`)
- Scripts will automatically prefer the original filename without duplicate suffixes
- If all files have duplicate suffixes, the most recent file is selected
- Clear messaging shows which file was selected during deployment

#### **Error Handling and Validation:**
- **Early Validation**: Scripts check for installer availability before attempting deployment
- **Directory Validation**: Verifies installer directory exists and is accessible
- **File Validation**: Confirms ZIP files are present and not corrupted
- **Helpful Error Messages**: Provides step-by-step instructions when installers are missing
- **Graceful Failure**: Scripts exit cleanly with clear guidance when validation fails

#### **Supported Installer Formats:**
- **ZIP files containing Vision One Endpoint Security Agent installer and supporting files**
- Scripts automatically detect the main executable within the ZIP
- Supports various Vision One Endpoint Security Agent installer versions and configurations

## 📚 **Documentation Files**

### **`README.md`** - Complete User Guide
**Purpose**: Comprehensive documentation for using the deployment tool
**Sections**:
- Quick start guide and usage examples
- Configuration instructions
- Troubleshooting guide
- Security considerations
- Command reference and parameters

### **`SECURITY.md`** - Security Guidelines
**Purpose**: Security best practices and considerations for deployment
**Topics**:
- Credential management and protection
- Network security requirements
- Audit trail and compliance
- Risk mitigation strategies

### **`NETWORK_SECURITY.md`** - Network Security Analysis
**Purpose**: Detailed analysis of credential transmission security and advanced protection
**Topics**:
- Network protocol security analysis
- Credential interception risks and mitigation
- HTTPS WinRM configuration
- Certificate-based authentication
- Security audit checklist

### **`FILE_OVERVIEW.md`** - This File
**Purpose**: Complete documentation of every file in the project
**Content**: Detailed purpose, features, and usage for each file

### **`PRODUCTION_CHECKLIST.md`** - Deployment Checklist
**Purpose**: Step-by-step checklist for production deployments
**Sections**:
- Pre-deployment setup and verification
- Deployment process and monitoring
- Post-deployment verification
- Troubleshooting and emergency procedures

## 🗂️ **Log and Output Files**

### **`deployment.log`** - Audit Trail
**Purpose**: Comprehensive log of all deployment activities
**Contains**:
- Deployment start/end times and duration
- Target hosts and deployment methods used
- Success/failure status for each host
- Error messages and troubleshooting information
- Credential usage and file operations (audit trail)
**Format**: Timestamped JSON entries for easy parsing

### **`discovered_hosts.txt`** - Network Scan Results (Generated)
**Purpose**: Output file from network scanning operations
**Created By**: `Scan-Network.ps1 -SaveToFile`
**Contains**: List of discovered live hosts from network scans
**Usage**: Can be used as input for `-TargetFile` parameter

## 🎯 **Quick Reference**

### **Essential Setup Before Use**
1. **`installer/`** - Place your unique Vision One Endpoint Security Agent installer ZIP file
2. **`hosts.txt`** - Add your target IP addresses (optional for batch deployment)
3. **No configuration editing required** - credentials and domain are prompted at runtime

### **Files to Copy to Target Machines**
1. **`configure_target_machine.bat`** - Run as Administrator
2. **`check_wmi_services.bat`** - Verify configuration

### **Main Deployment Commands**
```powershell
# Single host
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'

# Multiple hosts
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128'

# Network range
.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24'

# From file
.\Deploy-VisionOne.ps1 -TargetFile 'hosts.txt'
```

---
**Last Updated**: $(Get-Date -Format "yyyy-MM-dd")
**Total Files Documented**: 15 files + installer directory