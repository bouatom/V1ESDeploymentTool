# ============================================================================
# VisionOne SEP Network Scanner
# ============================================================================
#
# PURPOSE: Discover and identify Windows hosts in network ranges
# FEATURES:
#   - CIDR network scanning with concurrent ping operations
#   - Windows host filtering (tests admin share access)
#   - Save discovered hosts to file for batch deployment
#   - Progress tracking for large network scans
#   - Configurable concurrency and timeouts
#
# USAGE EXAMPLES:
#   .\Scan-Network.ps1 -CIDR '10.0.5.0/24'
#   .\Scan-Network.ps1 -CIDR '192.168.1.0/24' -WindowsOnly
#   .\Scan-Network.ps1 -CIDR '10.0.5.0/24' -SaveToFile -OutputFile 'my_hosts.txt'
#
# OUTPUT: Discovered hosts can be saved to file for use with Deploy-VisionOne.ps1
#
# ============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$CIDR,
    
    [switch]$WindowsOnly,
    [switch]$SaveToFile,
    [string]$OutputFile = "discovered_hosts.txt"
)

# Load configuration
. .\Config.ps1

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

function Get-NetworkHosts {
    param([string]$CIDR)
    
    Write-Log "Scanning network: $CIDR"
    
    try {
        # Parse CIDR notation
        if ($CIDR -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
            $networkIP = $matches[1]
            $subnetMask = [int]$matches[2]
        } else {
            throw "Invalid CIDR format. Use format like 10.0.5.0/24"
        }
        
        # Convert IP to integer
        $ipParts = $networkIP.Split('.')
        $networkInt = ([uint32]$ipParts[0] -shl 24) + ([uint32]$ipParts[1] -shl 16) + ([uint32]$ipParts[2] -shl 8) + [uint32]$ipParts[3]
        
        # Calculate network range
        $hostBits = 32 - $subnetMask
        $networkMask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, $hostBits))
        $networkAddress = $networkInt -band $networkMask
        $broadcastAddress = $networkAddress + [Math]::Pow(2, $hostBits) - 1
        
        # Generate host IPs
        $hostIPs = @()
        
        if ($subnetMask -eq 32) {
            # /32 is a single host
            $hostIPs += $networkIP
            Write-Log "Single host: $networkIP"
        } elseif ($subnetMask -eq 31) {
            # /31 has 2 hosts (no network/broadcast)
            for ($i = $networkAddress; $i -le $broadcastAddress; $i++) {
                $ip = "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
                $hostIPs += $ip
            }
        } else {
            # Normal networks (skip network and broadcast addresses)
            for ($i = $networkAddress + 1; $i -lt $broadcastAddress; $i++) {
                $ip = "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
                $hostIPs += $ip
            }
        }
        
        Write-Log "Network range: $($hostIPs.Count) possible hosts ($($hostIPs[0]) - $($hostIPs[-1]))"
        
        # Ping sweep
        Write-Log "Performing ping sweep..."
        $liveHosts = @()
        $maxConcurrent = $Global:DeploymentConfig.MaxConcurrentPings
        $jobs = @()
        
        $progress = 0
        foreach ($ip in $hostIPs) {
            # Limit concurrent jobs
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
            
            # Progress indicator
            $progress++
            if ($progress % 50 -eq 0) {
                Write-Log "Scanned $progress/$($hostIPs.Count) hosts..."
            }
        }
        
        # Collect results
        Write-Log "Waiting for ping sweep to complete..."
        $jobs | Wait-Job | Out-Null
        
        foreach ($job in $jobs) {
            $result = Receive-Job $job
            if ($result) {
                $liveHosts += $result
            }
            Remove-Job $job
        }
        
        Write-Log "Found $($liveHosts.Count) live hosts" "SUCCESS"
        
        return $liveHosts
        
    } catch {
        Write-Log "Error scanning network: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Test-WindowsHost {
    param([string]$HostIP)
    
    try {
        # Try to access admin share
        if (Test-Path "\\$HostIP\C$" -ErrorAction SilentlyContinue) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

# Main execution
Write-Host "=== Network Scanner for VisionOne SEP Deployment ===" -ForegroundColor Cyan
Write-Host "Scanning: $CIDR" -ForegroundColor White
Write-Host "Windows Only: $WindowsOnly" -ForegroundColor White
Write-Host ""

$startTime = Get-Date

# Scan for live hosts
$liveHosts = Get-NetworkHosts $CIDR

if ($liveHosts.Count -eq 0) {
    Write-Log "No live hosts found in $CIDR" "WARNING"
    exit 0
}

# Filter for Windows hosts if requested
if ($WindowsOnly) {
    Write-Log "Filtering for Windows hosts..."
    $windowsHosts = @()
    
    foreach ($targetHost in $liveHosts) {
        if (Test-WindowsHost $targetHost) {
            $windowsHosts += $targetHost
            Write-Log "  ✅ $targetHost (Windows)" "SUCCESS"
        } else {
            Write-Log "  ❌ $targetHost (Not Windows/No access)" "WARNING"
        }
    }
    
    $finalHosts = $windowsHosts
    Write-Log "Found $($windowsHosts.Count) Windows hosts out of $($liveHosts.Count) live hosts" "SUCCESS"
} else {
    $finalHosts = $liveHosts
    $finalHosts | ForEach-Object { Write-Log "  - $_" "SUCCESS" }
}

# Save to file if requested
if ($SaveToFile -and $finalHosts.Count -gt 0) {
    $finalHosts | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Log "Saved $($finalHosts.Count) hosts to $OutputFile" "SUCCESS"
}

# Summary
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "=== Scan Summary ===" -ForegroundColor Cyan
Write-Host "Network: $CIDR" -ForegroundColor White
Write-Host "Live hosts: $($liveHosts.Count)" -ForegroundColor Green
if ($WindowsOnly) {
    Write-Host "Windows hosts: $($finalHosts.Count)" -ForegroundColor Green
}
Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor White

if ($finalHosts.Count -gt 0) {
    Write-Host ""
    Write-Host "Ready for deployment:" -ForegroundColor Green
    Write-Host ".\Deploy-VisionOne.ps1 -TargetIPs '$($finalHosts -join "','")'" -ForegroundColor Yellow
    
    if ($SaveToFile) {
        Write-Host "Or using the saved file:" -ForegroundColor Green
        Write-Host ".\Deploy-VisionOne.ps1 -TargetFile '$OutputFile'" -ForegroundColor Yellow
    }
}