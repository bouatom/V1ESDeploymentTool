# Test script to verify local connection detection
. .\Deploy-VisionOne.ps1

Write-Host "Testing local connection detection..." -ForegroundColor Yellow

# Test various local identifiers
$testIPs = @(
    "localhost",
    "127.0.0.1",
    $env:COMPUTERNAME,
    "::1"
)

foreach ($ip in $testIPs) {
    $isLocal = Test-IsLocalMachine $ip
    Write-Host "Testing '$ip': $(if ($isLocal) { 'LOCAL' } else { 'REMOTE' })" -ForegroundColor $(if ($isLocal) { 'Green' } else { 'Red' })
}

# Test a clearly remote IP
$isLocal = Test-IsLocalMachine "192.168.1.100"
Write-Host "Testing '192.168.1.100': $(if ($isLocal) { 'LOCAL' } else { 'REMOTE' })" -ForegroundColor $(if ($isLocal) { 'Green' } else { 'Red' })

Write-Host "Test completed!" -ForegroundColor Yellow