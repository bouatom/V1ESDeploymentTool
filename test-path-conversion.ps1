# Test path conversion
. .\Config.ps1

Write-Host "Original RemoteTempPath: '$($Global:DeploymentConfig.RemoteTempPath)'"
$convertedPath = $Global:DeploymentConfig.RemoteTempPath.Replace('C$', 'C:')
Write-Host "Converted local path: '$convertedPath'"

# Test if path exists (it won't, but we can see if the conversion works)
Write-Host "Path exists: $(Test-Path $convertedPath)"

# Test creating the directory
try {
    New-Item -ItemType Directory -Path $convertedPath -Force | Out-Null
    Write-Host "Directory creation: SUCCESS"
    Write-Host "Actual path created: $(Get-Item $convertedPath).FullName"
} catch {
    Write-Host "Directory creation failed: $($_.Exception.Message)"
}