# Vision One Endpoint Security Agent Deployment - Production Checklist

## ✅ **Pre-Deployment Setup**

### **1. Configure Credentials**
- [ ] Edit `Config.ps1` with your domain credentials
- [ ] Test credentials manually: `Get-WmiObject -Class Win32_ComputerSystem -ComputerName <target> -Credential $cred`
- [ ] Secure the `Config.ps1` file (restrict file permissions)

### **2. Prepare Target Machines**
- [ ] Copy `configure_target_machine.bat` to target machines
- [ ] Run as Administrator on each target machine
- [ ] Verify with `check_wmi_services.bat`

### **3. Verify Installer**
- [ ] Ensure `installer/EndpointBasecamp.exe` exists
- [ ] Verify installer integrity and version
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

### **2. Scale Up**
```powershell
# Deploy to multiple machines
.\Deploy-VisionOne.ps1 -TargetIPs '10.0.5.127','10.0.5.128','10.0.5.129'

# Deploy to entire network
.\Deploy-VisionOne.ps1 -CIDR '10.0.5.0/24' -Parallel -MaxParallel 5
```

### **3. Monitor Progress**
- [ ] Watch console output for real-time status
- [ ] Check `deployment.log` for detailed audit trail
- [ ] Verify installations on target machines

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
- [ ] Remove installer files from target machines (`C:\temp\VisionOneSEP\`)
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
- **Clean up**: Remove files from `C:\temp\VisionOneSEP\` on targets

## 📊 **Success Metrics**

- [ ] **Deployment Success Rate**: >95% for prepared networks
- [ ] **Installation Verification**: All targets show Vision One processes
- [ ] **Management Console**: All agents appear and communicate
- [ ] **No Conflicts**: No errors with existing security software

## 🔒 **Security Considerations**

- [ ] **Credential Security**: `Config.ps1` has restricted permissions
- [ ] **Network Security**: Deployment from secure administrative workstation
- [ ] **Audit Trail**: `deployment.log` preserved for compliance
- [ ] **Clean Up**: Temporary files removed from target machines

## 📞 **Support Contacts**

- **Technical Issues**: [Your IT Support]
- **Vision One Support**: [Trend Micro Support]
- **Network Issues**: [Network Team]
- **Security Questions**: [Security Team]

---

**Last Updated**: $(Get-Date -Format "yyyy-MM-dd")
**Version**: 1.0 Production Ready