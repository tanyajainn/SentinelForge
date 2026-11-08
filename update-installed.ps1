#Requires -Version 5.1
#Requires -RunAsAdministrator
# Run from a reviewed build. This script never executes a binary as administrator.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$name = 'SentinelForge Security Monitor'
$task = Get-ScheduledTask -TaskPath '\' -TaskName $name
$account = $task.Principal.UserId
if ($account -match '^S-1-') {
    $sid = [Security.Principal.SecurityIdentifier]::new($account)
} else {
    $sid = ([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier])
}
if ($sid.Value -ne $identity.User.Value) { throw 'Run this as the account that owns the task.' }
if ($task.Actions.Count -ne 1) { throw 'Unexpected task actions. Inspect the task before updating.' }
$old = $task.Actions[0].Execute.Trim('"')
$programs = [Environment]::GetFolderPath('ProgramFiles')
$prefix = Join-Path $programs 'SentinelForge-'
$legacy = Join-Path $env:LOCALAPPDATA 'SentinelForge\bin\SentinelForgeAgent.exe'
$installedPattern = '^' + [regex]::Escape($prefix) + '[a-f0-9]{32}\\SentinelForgeAgent\.exe$'
if ($old -ine $legacy -and $old -notmatch $installedPattern) { throw "Unexpected agent path: $old" }

# Keep complete builds side by side. Never overwrite a running image or restore
# a highest-privilege task pointing to the legacy user-writable path.
$build = Join-Path $PSScriptRoot 'dist'
$files = 'SentinelForge.exe', 'SentinelForgeAgent.exe'
foreach ($file in $files) {
    if (!(Test-Path (Join-Path $build $file) -PathType Leaf)) { throw "Build missing: $file" }
}

$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($admins)
foreach ($group in @($admins, $system, $users)) {
    $rights = if ($group.Value -eq $users.Value) { 'ReadAndExecute' } else { 'FullControl' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $group, $rights, 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
}
$target = $prefix + [Guid]::NewGuid().ToString('N')
[IO.Directory]::CreateDirectory($target, $acl) | Out-Null
foreach ($file in $files) {
    $src = Join-Path $build $file
    $dest = Join-Path $target $file
    [IO.File]::Copy($src, $dest, $false)
    # Set the entire file ACL explicitly, including on copies from user-owned sources.
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner($admins)
    foreach ($group in @($admins, $system, $users)) {
        $rights = if ($group.Value -eq $users.Value) { 'ReadAndExecute' } else { 'FullControl' }
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($group, $rights, 'Allow'))
    }
    Set-Acl -LiteralPath $dest -AclObject $fileAcl
    if ((Get-FileHash $src).Hash -ne (Get-FileHash $dest).Hash) { throw "Copy verification failed: $file" }
}
$agent = Join-Path $target 'SentinelForgeAgent.exe'
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$action = New-ScheduledTaskAction -Execute $agent -WorkingDirectory $target
# Replace the definition first so subsequent logons use the limited principal.
Set-ScheduledTask -TaskPath '\' -TaskName $name -Principal $principal -Action $action | Out-Null
$newTask = Get-ScheduledTask -TaskPath '\' -TaskName $name
if ($newTask.Principal.RunLevel -ne 'Limited' -or $newTask.Actions[0].Execute -ine $agent) {
    throw 'Task verification failed. Inspect the task before starting it.'
}
Stop-ScheduledTask -TaskPath '\' -TaskName $name
# PyInstaller may have both a parent and a child. Stop only this exact old image.
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    $remaining = @(Get-Process -Name SentinelForgeAgent -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -ieq $old })
    if (!$remaining.Count) { break }
    foreach ($process in $remaining) {
        if (!$process.HasExited) { try { $process.Kill() } catch { if (!$process.HasExited) { throw } } }
    }
    Start-Sleep -Milliseconds 500
}
if (@(Get-Process -Name SentinelForgeAgent -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -ieq $old }).Count) { throw 'Previous agent still running. Task remains limited.' }
Start-ScheduledTask -TaskPath '\' -TaskName $name
Write-Host "Limited task registered. Installed CLI: $(Join-Path $target 'SentinelForge.exe')"
Write-Host 'Run that CLI from a normal PowerShell window for status and self-test.'
