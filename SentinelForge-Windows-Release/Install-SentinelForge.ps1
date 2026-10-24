$ErrorActionPreference = 'Stop'

$taskName = 'SentinelForge Security Monitor'
$target = Join-Path $env:LOCALAPPDATA 'SentinelForge\bin'
$cli = Join-Path $PSScriptRoot 'SentinelForge.exe'
$agent = Join-Path $PSScriptRoot 'SentinelForgeAgent.exe'

$admin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (!$admin) {
    throw 'Run PowerShell as Administrator using your own Windows account.'
}

if (!(Test-Path $cli) -or !(Test-Path $agent)) {
    throw 'Required SentinelForge executables are missing.'
}

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'SentinelForge is already installed. Existing installation preserved.'
}

foreach ($file in @(
    "$target\SentinelForge.exe",
    "$target\SentinelForgeApp.exe",
    "$target\SentinelForgeAgent.exe"
)) {
    if (Test-Path $file) {
        throw "Existing installation detected: $file"
    }
}

# Existing application setup installs executables,
# stores Gmail credentials in Windows Credential Manager,
# and registers the logon monitoring task.
& $cli setup

if ($LASTEXITCODE -ne 0) {
    throw 'SentinelForge setup failed.'
}

$installedCli = Join-Path $target 'SentinelForge.exe'
$app = Join-Path $target 'SentinelForgeApp.exe'

if (!(Test-Path $installedCli)) {
    throw 'Application setup did not install the CLI.'
}

# Rename the CLI so SentinelForge.cmd wins command lookup.
Rename-Item -LiteralPath $installedCli `
    -NewName 'SentinelForgeApp.exe' -ErrorAction Stop

$wrapper = Join-Path $target 'SentinelForge.cmd'

$wrapperLines = @(
    '@echo off',
    'if "%~1"=="" (',
    '    "%~dp0SentinelForgeApp.exe" status',
    ') else (',
    '    "%~dp0SentinelForgeApp.exe" %*',
    ')'
)

Set-Content -LiteralPath $wrapper `
    -Value $wrapperLines -Encoding ASCII

# Protected Security log needs an elevated monitoring task.
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop

$principal = New-ScheduledTaskPrincipal `
    -UserId $task.Principal.UserId `
    -LogonType Interactive `
    -RunLevel Highest

Set-ScheduledTask -TaskName $taskName `
    -Principal $principal -ErrorAction Stop | Out-Null

$verified = Get-ScheduledTask -TaskName $taskName

if ($verified.Principal.RunLevel -ne 'Highest') {
    throw 'Task elevation failed.'
}

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

# Register one-word command for the current Windows user.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @($userPath -split ';' | Where-Object { $_ })

if ($parts -notcontains $target) {
    [Environment]::SetEnvironmentVariable(
        'Path',
        (($parts + $target) -join ';'),
        'User'
    )
}

Write-Host ''
Write-Host 'INSTALLATION COMPLETE' -ForegroundColor Green
Write-Host 'Open a NEW PowerShell window and type: SentinelForge'
Write-Host 'Monitor runs at Windows login.'
Write-Host 'Confirm actual Gmail inbox delivery separately.'