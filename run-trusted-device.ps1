param(
    [string]$AppleID,
    [string]$StateDir = (Join-Path $PSScriptRoot 'state'),
    [string]$ADILibrary = (Join-Path $PSScriptRoot '.cache\openbubbles-store\rust_lib_bluebubbles.dll'),
    [string]$Python = 'python',
    [string]$RefreshEvery = '10m',
    [ValidateSet('trusted-device', 'sms', 'sms-existing', 'circle')]
    [string]$TwoFactor = 'trusted-device',
    [switch]$Check,
    [switch]$Background,
    [switch]$Status,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$StateDir = [IO.Path]::GetFullPath($StateDir)
$ADILibrary = [IO.Path]::GetFullPath($ADILibrary)
$taskExecutable = Join-Path $PSScriptRoot 'bin\trusted-device.exe'
$taskStatusPath = Join-Path $StateDir 'runtime.json'
$taskRunning = $null
$taskRuntime = $null
if (Test-Path -LiteralPath $taskStatusPath) {
    $taskRuntime = Get-Content -LiteralPath $taskStatusPath -Raw | ConvertFrom-Json
    if ($taskRuntime.running) {
        $taskCandidate = Get-Process -Id $taskRuntime.pid -ErrorAction SilentlyContinue
        if ($taskCandidate -and $taskCandidate.Path -in @($taskExecutable, (Join-Path $PSScriptRoot 'bin\trusted-device-gui.exe'))) { $taskRunning = $taskCandidate }
    }
}
if ($Status) {
    if (-not $taskRuntime) { Write-Host 'No saved runtime status.'; return }
    $taskRuntime.running = [bool]$taskRunning
	if (-not $taskRunning) {
		$taskRuntime.authenticated = $false
		$taskRuntime.push_connected = $false
		if ($taskRuntime.state -eq 'online') { $taskRuntime.state = 'process_not_running' }
	}
    $taskRuntime | ConvertTo-Json
    return
}
if ($Stop) {
    if (-not $taskRunning) { Write-Host 'No active trusted-device process.'; return }
    $taskStopPath = Join-Path $StateDir 'stop-request.json'
    [IO.File]::WriteAllText($taskStopPath, (@{ pid = $taskRunning.Id } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    if (-not $taskRunning.WaitForExit(20000)) { throw 'Graceful shutdown has not completed; inspect the runtime status.' }
    Write-Host 'Session listener stopped gracefully. Saved device identity and cookies are retained.'
    return
}
if ($taskRunning) {
    Write-Host ('Already online, PID ' + $taskRunning.Id + '. Use -Status or -Stop.')
    return
}
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot 'bin') | Out-Null
Push-Location $PSScriptRoot
try {
    & go build -o $taskExecutable ./cmd/trusted-device
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
} finally { Pop-Location }

$taskArgs = @('-native-adi', '-dir', $StateDir, '-adi-dll', $ADILibrary, '-python', $Python, '-twofactor', $TwoFactor, '-refresh-every', $RefreshEvery)
if ($Check) {
    & $taskExecutable @taskArgs -check
    if ($LASTEXITCODE -ne 0) { throw 'Local input check failed.' }
    return
}
if (-not $AppleID) {
    if ($env:APPLESERVICES_APPLEID) { $AppleID = $env:APPLESERVICES_APPLEID }
    else { $AppleID = Read-Host 'Apple ID' }
}
if ($env:APPLESERVICES_PASSWORD) { $taskPassword = ConvertTo-SecureString $env:APPLESERVICES_PASSWORD -AsPlainText -Force }
else { $taskPassword = Read-Host 'Apple ID password' -AsSecureString }
$taskOldAppleID = $env:APPLESERVICES_APPLEID
$taskOldPassword = $env:APPLESERVICES_PASSWORD
$taskBstr = [IntPtr]::Zero
try {
    $taskBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskPassword)
    $env:APPLESERVICES_APPLEID = $AppleID
    $env:APPLESERVICES_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskBstr)
    if ($Background) {
        New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
        $taskArgs += '-background'
        # Encode native argv according to Windows quoting rules; no shell text.
        $taskQuotedArgs = @($taskArgs | ForEach-Object { '"' + (($_ -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' })
        $taskProcess = Start-Process -FilePath $taskExecutable -ArgumentList ($taskQuotedArgs -join ' ') `
            -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $StateDir 'daemon.out.log') `
            -RedirectStandardError (Join-Path $StateDir 'daemon.err.log')
        $taskDeadline = [DateTime]::UtcNow.AddSeconds(90)
        while ([DateTime]::UtcNow -lt $taskDeadline) {
            if ($taskProcess.HasExited) { throw 'Background login stopped. Check state/daemon.err.log; if verification is required, run without -Background once.' }
            if (Test-Path -LiteralPath $taskStatusPath) {
                $taskRuntime = Get-Content -LiteralPath $taskStatusPath -Raw | ConvertFrom-Json
                if ($taskRuntime.pid -eq $taskProcess.Id -and $taskRuntime.state -eq 'online') {
                    Write-Host ('Online in background, PID ' + $taskProcess.Id + '. Device count: ' + $taskRuntime.device_count)
                    return
                }
            }
            Start-Sleep -Milliseconds 250
        }
        Write-Host ('Background startup is still in progress, PID ' + $taskProcess.Id + '. Use -Status.')
    } else {
        & $taskExecutable @taskArgs
        if ($LASTEXITCODE -ne 0) { throw 'Trusted device stopped. See the error above.' }
    }
} finally {
    $env:APPLESERVICES_APPLEID = $taskOldAppleID
    $env:APPLESERVICES_PASSWORD = $taskOldPassword
    if ($taskBstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskBstr) }
    $taskPassword.Dispose()
}
