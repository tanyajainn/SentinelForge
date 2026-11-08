#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run the verifier in normal PowerShell so the channel check uses your limited token.'
}
$task = Get-ScheduledTask -TaskPath '\' -TaskName 'SentinelForge Security Monitor'
if ($task.Principal.RunLevel -ne 'Limited' -or $task.Actions.Count -ne 1) { throw 'Unexpected task definition.' }
$exe = $task.Actions[0].Execute.Trim('"')
$prefix = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SentinelForge-'
if ($exe -notmatch ('^' + [regex]::Escape($prefix) + '[a-f0-9]{32}\\SentinelForgeAgent\.exe$')) {
    throw 'Task is not pointed at a protected SentinelForge build.'
}
$writeBits = [int][Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
foreach ($path in @((Split-Path $exe), $exe, (Join-Path (Split-Path $exe) 'SentinelForge.exe'))) {
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Unexpected reparse point: $path"
    }
    $acl = Get-Acl -LiteralPath $path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-32-544', 'S-1-5-18') {
        throw "Unexpected owner: $path"
    }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and ([int]$ace.FileSystemRights -band $writeBits) -and
            $ace.IdentityReference.Value -notin 'S-1-5-32-544', 'S-1-5-18') { throw "Unexpected write permission: $path" }
    }
}
Write-Host "PASS: Limited task, protected executable directory and files. Task state: $($task.State)"
$failed = @()
foreach ($channel in 'Security','System','Microsoft-Windows-Windows Defender/Operational') {
    try {
        Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop | Out-Null
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') {
            $failed += $channel
            Write-Warning "$channel : $($_.Exception.Message)"
            continue
        }
    }
    Write-Host "Readable: $channel"
}
if ($failed.Count) { throw 'One or more channels could not be read. See the release guide.' }
& (Join-Path (Split-Path $exe) 'SentinelForge.exe') status
if ($LASTEXITCODE -ne 0) { throw 'Installed CLI status check failed.' }
