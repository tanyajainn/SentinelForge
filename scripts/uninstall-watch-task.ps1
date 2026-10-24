Unregister-ScheduledTask -TaskName 'SentinelForge Watch' -Confirm:$false -ErrorAction SilentlyContinue
Write-Host 'Removed SentinelForge Watch scheduled task (database retained).'
