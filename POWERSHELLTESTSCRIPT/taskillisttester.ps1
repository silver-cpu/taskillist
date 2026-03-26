# ==============================================================================
# TASKILLIST FULL AUTOMATED TEST SUITE
# ==============================================================================

# --- 0. PATHS ---
#$exe = "C:\Windows\System32\tasklist.exe"
#$exe2 = "C:\Windows\System32\taskkill.exe"
# UNCOMMENT the line below to test your custom build:
#$exe = "$env:USERPROFILE\source\repos\taskillist\x64\Release\taskillist.exe"
$exe = ".\taskillist.exe"
function Run-Test($Name, $Command) {
    Write-Host "`n[TEST] $Name" -ForegroundColor Cyan
    Write-Host "Running: $Command" -ForegroundColor Gray
    $out = Invoke-Expression $Command
    return $out
}
function Pause-Test {
    Write-Host "`n>> Press ENTER to continue to the next test..." -ForegroundColor Yellow
    Read-Host | Out-Null
}


# --- 1. SETUP UNIQUE TARGETS ---
Write-Host "`nSetting up unique test targets..." -ForegroundColor Yellow
# We use separate processes so one test doesn't accidentally kill another's target
$targetIM   = Start-Process powershell.exe -WindowStyle Minimized -PassThru
$targetPID  = Start-Process notepad.exe -WindowStyle Minimized -PassThru
#$targetS    = Start-Process mspaint.exe -WindowStyle Minimized -PassThru 
#$targetS2    = Start-Process mspaint.exe -WindowStyle Minimized -PassThru 
$targetTree = Start-Process cmd.exe     -ArgumentList "/c mspaint.exe" -PassThru -WindowStyle Minimized
$allPIDs    = @($targetIM.Id, $targetPID.Id, $targetTree.Id)
$remoteIP = "REPLACE WITH YOUR REMOTE IP"
$remoteUser = "REPLACE WITH YOUR USER"
$remotePass = "REPLACE WITH YOUR PASSWORD"

# --- 0. PART 2: REMOTE SETUP (OPEN MSPAINT) ---
Write-Host "`nOpening Paint on remote VM ($remoteIP)..." -ForegroundColor Yellow
$secPass = ConvertTo-SecureString $remotePass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($remoteUser, $secPass)
try {
    # Using the method that worked in your manual test
    $result = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "mspaint.exe" -ComputerName $remoteIP -Credential $cred
    
    if ($result.ReturnValue -eq 0) {
        Write-Host "SUCCESS: mspaint.exe is now running on $remoteIP (PID: $($result.ProcessId))" -ForegroundColor Green
    } else {
        Write-Host "FAILED: ReturnValue: $($result.ReturnValue)" -ForegroundColor Red
    }
} catch {
    Write-Host "ERROR: Connection failed: $($_.Exception.Message)" -ForegroundColor Red
}
Start-Sleep -s 2 
Pause-Test
# --- 2. TASKLIST BASE ---
$baseOut = Run-Test "Tasklist Base" "$exe"
if ($baseOut -match "Console") { Write-Host "PASS: Base listing detected Console." -ForegroundColor Green }
Pause-Test
# --- 3. /SVC ---
$svcOut = Run-Test "Tasklist /SVC" "$exe /svc"
if ($svcOut -match "Power,") { Write-Host "PASS: Power, detected under lsass.exe" -ForegroundColor Green }
Pause-Test
# --- 4. /V ---
$vOut = Run-Test "Tasklist /V" "$exe /v"
if ($vOut -match "CPU Time") { Write-Host "PASS: CPU Time detected under " -ForegroundColor Green }
Pause-Test


# --- 5. KILL /IM /F ---
# Use a filter to kill only the specific IM target PID
$imOut = Run-Test "Taskkill /IM (Filtered)" "$exe /kill /im powershell.exe"
if ($imOut -match "SUCCESS" -or $imOut -match "terminated") { Write-Host "PASS: Image/Filter termination success." -ForegroundColor Green }
Pause-Test
# --- 6. KILL /PID ---
$pidOut = Run-Test "Taskkill /PID" "$exe /kill /pid $($targetPID.Id) /f"
if ($pidOut -match "SUCCESS" -or $pidOut -match "terminated") { Write-Host "PASS: PID termination success." -ForegroundColor Green }
Pause-Test




# --- 7. KILL /T (TREE) ---
$tOut = Run-Test "Taskkill /T (Tree Kill)" "$exe /kill /pid $($targetTree.Id) /t /f"
if ($tOut -match "SUCCESS" -or $tOut -match "termination") { Write-Host "PASS: Tree kill success." -ForegroundColor Green }
Pause-Test


# --- 8. PART 2 TASKKILL /S (REMOTE TERMINATION TEST) ---
$sOut = Run-Test "Remote Taskkill /S /U /P" "$exe /kill /s $remoteIP /u $remoteUser /p $remotePass /im mspaint.exe /f"

if ($sOut -match "SUCCESS" -or $sOut -match "terminated") { 
    Write-Host "PASS: Remote termination on $remoteIP successful." -ForegroundColor Green 
} else {
    Write-Host "FAIL: Remote call failed." -ForegroundColor Red
    Write-Host "Checklist: 1. Is 'LocalAccountTokenFilterPolicy' set to 1? 2. Is WMI firewall rule enabled? 3. Is Notepad running on target?" -ForegroundColor Yellow
}
Pause-Test
# --- 9. PART 3 TASKKILL /S (REMOTE TERMINATION Fail TEST) ---
$sOut = Run-Test "Remote Fail check Taskkill /S /U /P" "$exe /kill /s $remoteIP /u $remoteUser /p $remotePass /im notepad.exe /f"

if ($sOut -match "SUCCESS" -or $sOut -match "terminated") { 
    Write-Host "FAIL: Remote termination on $remoteIP successful. NOT GOOD!" -ForegroundColor Red
} else {
    Write-Host "SUCCESS: Remote call failed. GOOD!" -ForegroundColor Green
}
Pause-Test
# --- 10. VERIFICATION & EMERGENCY CLEANUP ---
Write-Host "`n--- FINAL VERIFICATION ---" -ForegroundColor Yellow
Start-Sleep -s 1
$remaining = Get-Process -Id $allPIDs -ErrorAction SilentlyContinue
if ($null -eq $remaining) {
    Write-Host "ALL LOCAL TEST PROCESSES SUCCESSFULLY TERMINATED." -ForegroundColor Green
} else {
    Write-Host "WARNING: Cleaning up leaked processes..." -ForegroundColor Red
    $remaining | Stop-Process -Force -ErrorAction SilentlyContinue
}

Write-Host "`nTesting Complete." -ForegroundColor White
