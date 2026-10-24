$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

if (!$principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run PowerShell as Administrator using your own Windows account."
}

$taskName = "SentinelForge Security Monitor"
$target = Join-Path $env:LOCALAPPDATA "SentinelForge\bin"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "SentinelForge is already installed. Existing installation protected."
}

if ((Test-Path (Join-Path $target "SentinelForge.exe")) -or
    (Test-Path (Join-Path $target "SentinelForgeAgent.exe"))) {
    throw "Existing SentinelForge installation detected."
}

foreach ($file in @("SentinelForge.exe", "SentinelForgeAgent.exe")) {
    if (!(Test-Path (Join-Path $PSScriptRoot $file))) {
        throw "Missing $file. Extract the complete ZIP."
    }
}

New-Item -ItemType Directory -Path $target -Force | Out-Null

foreach ($file in @("SentinelForge.exe", "SentinelForgeAgent.exe")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) `
        -Destination (Join-Path $target $file) -Force
}

$cli = Join-Path $target "SentinelForge.exe"

& $cli setup
if ($LASTEXITCODE -ne 0) {
    throw "SentinelForge setup failed."
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
$taskUser = $task.Principal.UserId

if ([string]::IsNullOrWhiteSpace($taskUser)) {
    throw "Task user could not be verified."
}

try {
    $actualSid = ([Security.Principal.NTAccount]::new(
        $taskUser
    )).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}
catch {
    throw "Could not verify the scheduled task account."
}

if ($actualSid -ne $identity.User.Value) {
    throw "Scheduled task account differs from the installation account."
}

$newPrincipal = New-ScheduledTaskPrincipal `
    -UserId $taskUser `
    -LogonType Interactive `
    -RunLevel Highest

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

Set-ScheduledTask -TaskName $taskName `
    -Principal $newPrincipal -ErrorAction Stop | Out-Null

Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

$task = Get-ScheduledTask -TaskName $taskName

if ($task.Principal.RunLevel -ne "Highest") {
    throw "Background monitor does not have required privileges."
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$paths = @($userPath -split ";" | Where-Object {
    $_ -and ($_.TrimEnd("\") -ine $target.TrimEnd("\"))
})

[Environment]::SetEnvironmentVariable(
    "Path",
    (($paths + $target) -join ";"),
    "User"
)

& $cli --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "SentinelForge CLI test failed."
}

Write-Host "PASS: SentinelForge installed." -ForegroundColor Green
Write-Host "PASS: One-word CLI configured." -ForegroundColor Green
Write-Host "PASS: Background monitor configured with Highest privileges." -ForegroundColor Green
Write-Host "Open a new PowerShell window and type: SentinelForge"
Write-Host "Check Gmail delivery separately after setup."
