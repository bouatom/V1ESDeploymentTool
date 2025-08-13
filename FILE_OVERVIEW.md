# VisionOne SEP Deployment Tool - Complete File Documentation

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

### **`Config.ps1`** - Master Configuration
**Purpose**: Central configuration file for all deployment settings
**Contains**:
- **Credentials**: Domain username, password, domain (MUST BE EDITED)
- **Paths**: Installer directory, remote temp paths
- **Timeouts**: Installation, monitoring, network scan timeouts
- **Security Settings**: Existing product checks, force installation flags
- **Network Options**: Concurrent operations, Windows-only filtering
**Critical**: Edit credentials before first use

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

### **`installer/`** - VisionOne SEP Installer Directory
**Purpose**: Contains all files needed for VisionOne SEP installation

#### **`installer/EndpointBasecamp.exe`** - Main Installer Executable
**Purpose**: Trend Micro VisionOne SEP agent installer
**Type**: Windows executable installer
**Usage**: Automatically copied to target machines and executed

#### **`installer/config.json`** - Installer Configuration
**Purpose**: Configuration file for the VisionOne SEP installer
**Contains**: Installation parameters, server settings, policy configurations
**Usage**: Automatically copied with installer to target machines

#### **`installer/packages/`** - Supporting Installation Files
**Purpose**: Additional files and dependencies required by the installer
**Contents**: Various subdirectories with installer components and dependencies
**Usage**: Entire directory structure copied to target machines

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

### **Essential Files to Edit Before Use**
1. **`Config.ps1`** - Add your domain credentials
2. **`hosts.txt`** - Add your target IP addresses (optional)

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