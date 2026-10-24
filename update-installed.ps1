# Existing-install updater. Does not change credentials, DB, baseline, triggers or task settings.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$taskName = 'SentinelForge Security Monitor'
$bin = Join-Path $env:LOCALAPPDATA 'SentinelForge\bin'
$oldAgent = Join-Path $bin 'SentinelForgeAgent.exe'
$oldCLI = Join-Path $bin 'SentinelForgeApp.exe'
$cliBuild = Join-Path $PSScriptRoot 'dist\SentinelForge.exe'
$agentBuild = Join-Path $PSScriptRoot 'dist\SentinelForgeAgent.exe'
if (!(Test-Path $oldAgent) -or !(Test-Path $oldCLI) -or !(Test-Path $cliBuild) -or !(Test-Path $agentBuild)) {
    throw 'Required executables missing. Existing installation not modified.'
}
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
$expected = [IO.Path]::GetFullPath($oldAgent)
if (!$task.Actions -or $task.Actions[0].Execute.Trim('"') -ine $expected) {
    throw 'Scheduled task points to an unexpected executable. Existing installation not modified.'
}
$backup = Join-Path $bin ('backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup | Out-Null
Copy-Item $oldAgent $backup -ErrorAction Stop
Copy-Item $oldCLI $backup -ErrorAction Stop
Write-Host "Backed up installed executables to: $backup"
$wasRunning = $task.State -eq 'Running'
try {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath -ieq $expected
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }
    Start-Sleep -Seconds 3
    Copy-Item $agentBuild $oldAgent -Force -ErrorAction Stop
    Copy-Item $cliBuild $oldCLI -Force -ErrorAction Stop
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Start-Sleep -Seconds 5
    & $oldCLI status
    if ($LASTEXITCODE -ne 0) { throw 'Status smoke test failed after updating.' }
    Write-Host 'Update installed. Next, run SentinelForge self-test to check live delivery.' -ForegroundColor Green
}
catch {
    $originalError = $_
    Write-Warning 'Update failed; attempting to restore executable backups.'
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath -ieq $expected
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3
    Copy-Item (Join-Path $backup 'SentinelForgeAgent.exe') $oldAgent -Force
    Copy-Item (Join-Path $backup 'SentinelForgeApp.exe') $oldCLI -Force
    if ($wasRunning) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw $originalError
}
