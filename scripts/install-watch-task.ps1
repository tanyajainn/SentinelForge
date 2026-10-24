# Run elevated. Task runs at logon under current account; Windows event log access may require elevation.
param([int]$Interval = 60)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = (Get-Command python.exe -ErrorAction Stop).Source
$logdir = Join-Path $env:USERPROFILE 'SentinelForgeData'
New-Item -ItemType Directory -Force -Path $logdir | Out-Null
$runner = Join-Path $logdir 'run-watch.ps1'
# No secrets stored in this runner. For alerts, configure a private endpoint securely for the task account.
@"
Set-Location '$($project.Replace("'", "''"))'
& '$($python.Replace("'", "''"))' -m sentinelforge watch --interval $Interval --quiet *>> '$($logdir.Replace("'", "''"))\watch.log'
"@ | Set-Content -Encoding UTF8 $runner
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'SentinelForge Watch' -Action $action -Trigger $trigger -Settings $settings -Description 'Local Windows event log monitor' -Force | Out-Null
Write-Host 'Task installed for logon. Start manually: Start-ScheduledTask -TaskName "SentinelForge Watch"'
Write-Host 'IMPORTANT: This task does not inherit your interactive PowerShell notification environment variables.'
