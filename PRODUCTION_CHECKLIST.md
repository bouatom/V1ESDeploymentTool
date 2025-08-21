# Vision One Endpoint Security Agent Deployment - Production Checklist (v2.0)

## ✅ **Pre-Deployment Setup**

### **1. Prepare Credentials**
- [ ] Ensure you have an account with administrator permissions on target machines
- [ ] Know your domain name (e.g., CONTOSO, your.domain.com)
- [ ] Test credentials manually: `Get-WmiObject -Class Win32_ComputerSystem -ComputerName <target> -Credential $cred`
- [ ] **No configuration files to edit** - credentials are prompted at runtime

### **1.1. Performance Optimization Assessment (New in v2.0)**
- [ ] Check system resources: `.\Deploy-VisionOne.ps1 -ShowParallelConfig`
- [ ] Review parallel deployment recommendations based on your system
- [ ] Adjust `MaxParallelDeployments` in Config.ps1 if needed (default: 5)
- [ ] Consider PowerShell 7+ for 20-30% better performance

### **2. Prepare Target Machines**
- [ ] Copy `configure_target_machine.bat` to target machines
- [ ] Run as Administrator on each target machine
- [ ] Verify with `check_wmi_services.bat`

### **3. Verify Installer**
- [ ] Place your unique Vision One Endpoint Security Agent installer ZIP in `installer/` directory
- [ ] Verify installer ZIP file integrity and version
- [ ] Test manual installation on one machine first

### **4. Network Preparation**
- [ ] Verify network connectivity to target machines
- [ ] Ensure admin share access (`\\target\C$`)
- [ ] Test WMI connectivity manually

## 🚀 **Deployment Process**

### **1. Start Small**
```powershell
# Test connectivity first
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127' -TestOnly

# Deploy to single machine
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127'
```

### **2. Scale Up with Performance Optimization (Enhanced in v2.0)**
```powershell
# Deploy to multiple machines (automatic parallel for 4+ hosts)
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128','10.0.5.129','10.0.5.130'

# Deploy to entire network with custom parallel limit
.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -ParallelLimit 8

# High-performance deployment for large networks
.\Deploy-VisionOne.ps1 -CIDR '10.0.0.1/16' -ParallelLimit 15

# Force parallel deployment even for few hosts
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128' -FullParallel
```

### **3. Monitor Progress (Enhanced in v2.0)**
- [ ] Watch console output for real-time status with performance timing
- [ ] Monitor parallel deployment progress with batch completion updates
- [ ] Check `deployment.log` for detailed audit trail
- [ ] Verify installations using 5-method verification system
- [ ] Review performance metrics and optimization recommendations

## 🔧 **v2.0 Feature Validation**

### **1. Performance Features**
- [ ] **Caching System**: Verify local detection caching is working (should see "Detected local/remote connection" only once per host)
- [ ] **Parallel Processing**: Confirm parallel deployment is active for 4+ hosts (automatic) or when using `-FullParallel`
- [ ] **Memory Management**: Monitor memory usage during large deployments (should remain stable)
- [ ] **Performance Timing**: Check for performance timing logs (e.g., "Performance: Deploy-10.0.0.10 completed in 45.23 seconds")

### **2. Reliability Features**
- [ ] **Multi-Method Verification**: Verify installation success detection uses multiple methods (WMI, services, files, registry, PowerShell Remoting)
- [ ] **Local Connection Handling**: Test local deployment (should automatically detect and optimize)
- [ ] **TrustedHosts Management**: Verify automatic TrustedHosts configuration and restoration
- [ ] **Enhanced Error Handling**: Test graceful degradation when WMI/RPC fails

### **3. Smart Features**
- [ ] **Automatic Skipping**: Verify machines with existing Trend Micro are skipped (configurable in Config.ps1)
- [ ] **System Optimization**: Check parallel deployment recommendations match your system resources
- [ ] **Progress Monitoring**: Confirm real-time progress updates during deployment
- [ ] **Comprehensive Logging**: Verify detailed method-by-method verification results

## 📊 **Performance Benchmarking**

### **Expected Performance Improvements**
- [ ] **Small Networks (5 hosts)**: Should be ~75% faster than sequential
- [ ] **Medium Networks (20 hosts)**: Should be ~80% faster than sequential  
- [ ] **Large Networks (50+ hosts)**: Should be ~80% faster than sequential
- [ ] **Local Detection**: Should be near-instant after first call (caching)
- [ ] **Network Scanning**: Should show parallel processing for PowerShell 7+

### **Performance Validation Commands**
```powershell
# Test local connection detection performance
.\test-local-connection.ps1

# Test path conversion functionality  
.\test-path-conversion.ps1

# Show system recommendations
.\Deploy-VisionOne.ps1 -ShowParallelConfig

# Benchmark small deployment
Measure-Command { .\Deploy-VisionOne.ps1 -TargetIPs '10.0.0.10','10.0.0.11' -TestOnly }
```

## 🔍 **Post-Deployment Verification**

### **1. Check Installation Status**
- [ ] Verify Vision One processes are running on targets
- [ ] Check Windows Services for Trend Micro services
- [ ] Confirm agent communication with management console

### **2. Review Logs**
- [ ] Check `deployment.log` for any errors or warnings
- [ ] Review Windows Event Logs on target machines
- [ ] Verify no conflicts with existing security software

### **3. Clean Up**
- [ ] Remove installer files from target machines (`C:\temp\Trend Micro\V1ES\`)
- [ ] Archive deployment logs
- [ ] Document any issues or special configurations

## ⚠️ **Troubleshooting**

### **Common Issues**
1. **"Credentials rejected"** → Check domain credentials, run `configure_target_machine.bat`
2. **"Access denied"** → Verify admin privileges and network access
3. **"File copy failed"** → Check admin share access (`\\target\C$`)
4. **"WMI connection failed"** → Run WMI configuration on target machine

### **Emergency Procedures**
- **Stop deployment**: Press Ctrl+C to interrupt
- **Rollback**: Use Vision One management console to uninstall
- **Clean up**: Remove files from `C:\temp\Trend Micro\V1ES\` on targets

## 📊 **Success Metrics**

- [ ] **Deployment Success Rate**: >95% for prepared networks
- [ ] **Installation Verification**: All targets show Vision One processes
- [ ] **Management Console**: All agents appear and communicate
- [ ] **No Conflicts**: No errors with existing security software

## 🔒 **Security Considerations**

- [ ] **Credential Security**: No credentials stored in files - prompted at runtime
- [ ] **Network Security**: Deployment from secure administrative workstation
- [ ] **Audit Trail**: `deployment.log` preserved for compliance
- [ ] **Clean Up**: Temporary files removed from target machines

---

**Last Updated**: $(Get-Date -Format "yyyy-MM-dd")
**Version**: 1.0 Production Ready
