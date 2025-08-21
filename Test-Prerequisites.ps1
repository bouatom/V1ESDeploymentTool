#Requires -Version 5.1
<#
.SYNOPSIS
    Tests system prerequisites for Vision One Endpoint Security Agent Deployment Tool

.DESCRIPTION
    This script validates that the system meets all requirements for running
    the Vision One Endpoint Security Agent Deployment Tool without making any changes.

.EXAMPLE
    .\Test-Prerequisites.ps1

.NOTES
    Author: Vision One Endpoint Security Agent Deployment Tool
    Version: 1.0
    This script can be run without administrator privileges
#>

[CmdletBinding()]
param()

# Color output functions
function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Info { param($Message) Write-Host "ℹ️  $Message" -ForegroundColor Cyan }
function Write-Warn { param($Message) Write-Host "⚠️  $Message" -ForegroundColor Yellow }
function Write-Fail { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }

function Test-AllPrerequisites {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║       Vision One Endpoint Security Agent Deployment Tool    ║
║              Prerequisites Checker                           ║
╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    $allPassed = $true
    
    # Test Windows version
    Write-Host "🔍 Checking Windows Version..." -ForegroundColor Magenta
    $osVersion = [System.Environment]::OSVersion.Version
    $osName = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    
    if ($osVersion.Major -ge 10) {
        Write-Success "Windows Version: $osName ($osVersion)"
    }
    else {
        Write-Fail "Windows Version: $osName ($osVersion) - Windows 10/Server 2016+ required"
        $allPassed = $false
    }
    
    # Test PowerShell version
    Write-Host "`n🔍 Checking PowerShell Version..." -ForegroundColor Magenta
    $psVersion = $PSVersionTable.PSVersion
    
    if ($psVersion.Major -ge 5) {
        Write-Success "PowerShell Version: $psVersion"
    }
    else {
        Write-Fail "PowerShell Version: $psVersion - PowerShell 5.1+ required"
        $allPassed = $false
    }
    
    # Test administrator privileges
    Write-Host "`n🔍 Checking Administrator Privileges..." -ForegroundColor Magenta
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-Success "Administrator Privileges: Available"
    }
    else {
        Write-Warn "Administrator Privileges: Not running as administrator"
        Write-Info "Installation will require administrator privileges"
    }
    
    # Test disk space
    Write-Host "`n🔍 Checking Disk Space..." -ForegroundColor Magenta
    try {
        $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)
        
        if ($freeSpaceGB -ge 2) {
            Write-Success "Disk Space: $freeSpaceGB GB free of $totalSpaceGB GB total"
        }
        else {
            Write-Fail "Disk Space: $freeSpaceGB GB free - At least 2GB required"
            $allPassed = $false
        }
    }
    catch {
        Write-Warn "Could not check disk space: $($_.Exception.Message)"
    }
    
    # Test Python installation
    Write-Host "`n🔍 Checking Python Installation..." -ForegroundColor Magenta
    try {
        $pythonVersion = & python --version 2>&1
        if ($pythonVersion -match "Python (\d+)\.(\d+)\.(\d+)") {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            if ($major -eq 3 -and $minor -ge 7) {
                Write-Success "Python: $pythonVersion (Compatible)"
            }
            elseif ($major -eq 3) {
                Write-Warn "Python: $pythonVersion (Version 3.7+ recommended)"
            }
            else {
                Write-Fail "Python: $pythonVersion (Python 3.7+ required)"
                $allPassed = $false
            }
        }
        else {
            Write-Warn "Python: Installed but version could not be determined"
        }
    }
    catch {
        Write-Info "Python: Not installed or not in PATH (will be installed automatically)"
    }
    
    # Test network connectivity
    Write-Host "`n🔍 Checking Network Connectivity..." -ForegroundColor Magenta
    try {
        $testConnection = Test-NetConnection -ComputerName "www.python.org" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($testConnection) {
            Write-Success "Internet Connectivity: Available (required for Python installation)"
        }
        else {
            Write-Warn "Internet Connectivity: Limited (may affect Python installation)"
        }
    }
    catch {
        Write-Warn "Could not test internet connectivity"
    }
    
    # Test WinRM service
    Write-Host "`n🔍 Checking WinRM Service..." -ForegroundColor Magenta
    try {
        $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrmService) {
            if ($winrmService.Status -eq "Running") {
                Write-Success "WinRM Service: Running"
            }
            else {
                Write-Info "WinRM Service: Stopped (will be configured during installation)"
            }
        }
        else {
            Write-Info "WinRM Service: Not found (will be configured during installation)"
        }
    }
    catch {
        Write-Info "WinRM Service: Could not check status"
    }
    
    # Test Windows Firewall
    Write-Host "`n🔍 Checking Windows Firewall..." -ForegroundColor Magenta
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $enabledProfiles = $firewallProfiles | Where-Object { $_.Enabled -eq $true }
        
        if ($enabledProfiles.Count -gt 0) {
            Write-Info "Windows Firewall: Enabled on $($enabledProfiles.Count) profile(s)"
            Write-Info "Firewall rules will be configured during installation"
        }
        else {
            Write-Success "Windows Firewall: Disabled (no configuration needed)"
        }
    }
    catch {
        Write-Info "Windows Firewall: Could not check status"
    }
    
    # Test execution policy
    Write-Host "`n🔍 Checking PowerShell Execution Policy..." -ForegroundColor Magenta
    $executionPolicy = Get-ExecutionPolicy
    
    if ($executionPolicy -eq "Restricted") {
        Write-Warn "Execution Policy: $executionPolicy (may prevent script execution)"
        Write-Info "Installation script will handle execution policy temporarily"
    }
    else {
        Write-Success "Execution Policy: $executionPolicy"
    }
    
    # Summary
    Write-Host "`n" + "="*70 -ForegroundColor Cyan
    if ($allPassed) {
        Write-Success "✅ All critical prerequisites met!"
        Write-Info "System is ready for Vision One Endpoint Security Agent Deployment Tool installation"
        Write-Host "`nTo deploy, run: .\Deploy-VisionOne.ps1 -TargetIPs '<target-ip>'" -ForegroundColor Yellow
    }
    else {
        Write-Fail "❌ Some critical prerequisites are not met"
        Write-Info "Please address the issues above before installation"
    }
    
    Write-Host "`n📋 Installation Requirements Summary:"
    Write-Host "   • Windows 10/11 or Windows Server 2016+"
    Write-Host "   • PowerShell 5.1+"
    Write-Host "   • Administrator privileges"
    Write-Host "   • 2GB+ free disk space"
    Write-Host "   • Internet connectivity (for Python installation)"
    Write-Host "   • Python 3.7+ (will be installed if missing)"
    
    return $allPassed
}

# Run the test
try {
    Test-AllPrerequisites
}
catch {
    Write-Error "Prerequisites check failed: $($_.Exception.Message)"
    exit 1
}