# Project Aegis: Federal Log Simulator
# This script generates NIST-mapped security events for real-time auditing.

$logFile = "test_audit.log"
if (-Not (Test-Path $logFile)) { New-Item -ItemType File -Path $logFile }

Write-Host "🚀 Project Aegis Simulator: Generating NIST-mapped event stream..." -ForegroundColor Cyan
Write-Host "Target: $logFile" -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop.`n"

$events = @(
    "Apr 03 08:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2", # AU-2
    "Apr 03 08:00:05 server sudo: auth failure; logname=admin uid=0 euid=0 tty=/dev/pts/0 ruser=ruser rhost= user=root", # AC-3
    "Apr 03 08:00:10 server sshd[5678]: Accepted password for user1 from 10.0.0.5 port 12345 ssh2", # Noise
    "Apr 03 08:00:15 server sshd[9012]: Failed password for invalid user binary from 203.0.113.1 port 9999 ssh2", # AU-2
    "Apr 03 08:00:20 server kernel: [1234.56] usb 1-1: new high-speed USB device number 2 using xhci_hcd" # Noise
)

while ($true) {
    $event = $events | Get-Random
    $timestamp = Get-Date -Format "MMM dd HH:mm:ss"
    $fullLine = "$timestamp " + $event.Substring(14)
    
    try {
        $FileStream = [System.IO.FileStream]::new($logFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $StreamWriter = [System.IO.StreamWriter]::new($FileStream)
        $StreamWriter.WriteLine($fullLine)
        $StreamWriter.Dispose()
        $FileStream.Dispose()
        Write-Host " [+] Generated Log: $fullLine" -ForegroundColor Green
    } catch {
        Write-Host " [!] Access collision for $logFile. Retrying..." -ForegroundColor White
    }
    
    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
}
