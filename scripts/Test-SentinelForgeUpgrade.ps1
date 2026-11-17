#Requires -Version 5.1
<#
.SYNOPSIS
Read-only security preflight for an existing SentinelForge scheduled task.
.DESCRIPTION
Never registers, stops, modifies, or starts tasks; never runs executables.
This is a PRECONDITION check, not a complete installer security approval.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$BuildDirectory = (Join-Path $PSScriptRoot '..\dist'),
    [Parameter(Mandatory = $false)][string]$TaskName = 'SentinelForge Security Monitor'
)
$ErrorActionPreference = 'Stop'
$issues = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$items = @('SentinelForge.exe', 'SentinelForgeAgent.exe')
$evidence = [ordered]@{ taskName = $TaskName; taskAccount = $null; runLevel = $null; action = $null; installedBinaryHashes = @{}; buildBinaryHashes = @{}; signatures = @{} }

function Add-Issue([string]$text) { $script:issues.Add($text) }
function Add-Warning([string]$text) { $script:warnings.Add($text) }

function Test-SafeAcl([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    $ownerName = $acl.Owner
    try { $ownerSid = ([Security.Principal.NTAccount]$ownerName).Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { $ownerSid = $ownerName }
    if ($ownerSid -notin @('S-1-5-32-544', 'S-1-5-18')) {
        Add-Issue "Untrusted owner for protected path: $path"
    }
    $untrusted = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    $write = [Security.AccessControl.FileSystemRights]::Write -bor
             [Security.AccessControl.FileSystemRights]::Modify -bor
             [Security.AccessControl.FileSystemRights]::FullControl -bor
             [Security.AccessControl.FileSystemRights]::Delete -bor
             [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
             [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if ($sid -in $untrusted -and $rule.AccessControlType -eq 'Allow' -and
            (([int]$rule.FileSystemRights -band [int]$write) -ne 0)) {
            Add-Issue "Untrusted group has modification rights on: $path"
        }
    }
}

try {
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction Stop
    if ($task.Actions.Count -ne 1) { Add-Issue 'Expected exactly one scheduled-task action' }
    $evidence.taskAccount = $task.Principal.UserId
    $evidence.runLevel = [string]$task.Principal.RunLevel
    if ($evidence.runLevel -ne 'Limited') { Add-Issue 'Scheduled task does not use Limited run level' }
    if ([string]$task.Principal.LogonType -ne 'Interactive') { Add-Issue 'Scheduled task is not Interactive logon type' }
    if ($task.Actions.Count -eq 1) {
        $action = $task.Actions[0]
        $binary = $action.Execute.Trim('"')
        $evidence.action = $binary
        if (-not [string]::IsNullOrWhiteSpace($action.Arguments)) { Add-Issue 'Unexpected scheduled-task arguments' }
        $programs = [Environment]::GetFolderPath('ProgramFiles')
        $pattern = '^' + [regex]::Escape((Join-Path $programs 'SentinelForge-')) + '[a-fA-F0-9]{32}\\SentinelForgeAgent\.exe$'
        if ($binary -cnotmatch $pattern) { Add-Issue 'Agent is not in a recognized protected Program Files directory' }
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { Add-Issue 'Installed agent executable missing' }
        else {
            $folder = Split-Path -Parent $binary
            foreach ($path in @($folder, $binary)) {
                $attrs = (Get-Item -LiteralPath $path -Force).Attributes
                if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Add-Issue "Reparse point in protected installation: $path" }
                Test-SafeAcl $path
            }
            foreach ($filename in $items) {
                $path = Join-Path $folder $filename
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $evidence.installedBinaryHashes[$filename] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                } else { Add-Issue "Missing installed binary: $filename" }
            }
        }
    }
} catch { Add-Issue ('Cannot inspect installed scheduled task: ' + $_.Exception.Message) }

try {
    $build = (Resolve-Path -LiteralPath $BuildDirectory -ErrorAction Stop).Path
    foreach ($filename in $items) {
        $path = Join-Path $build $filename
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Add-Issue "Missing proposed build artifact: $filename"; continue }
        $info = Get-Item -LiteralPath $path -Force
        if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Add-Issue "Build artifact is a reparse point: $filename"; continue }
        if ($info.Length -le 0) { Add-Issue "Build artifact is empty: $filename"; continue }
        $evidence.buildBinaryHashes[$filename] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        $evidence.signatures[$filename] = [string]$signature.Status
        if ($signature.Status -ne 'Valid') { Add-Warning "Build artifact not verified as Authenticode-signed: $filename" }
    }
} catch { Add-Issue ('Cannot inspect proposed build: ' + $_.Exception.Message) }

$result = [pscustomobject]@{
    schema = 1
    operation = 'read-only-preflight'
    passed = ($issues.Count -eq 0)
    issues = @($issues)
    warnings = @($warnings)
    evidence = $evidence
}
$result | ConvertTo-Json -Depth 6
if (-not $result.passed) { exit 2 }
