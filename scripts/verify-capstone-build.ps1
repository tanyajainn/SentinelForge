# Read-only verification of an already-built SentinelForge distribution.
# Does not install, register tasks, configure email, or alter any running agent.
[CmdletBinding()]
param(
    [string]$ZipPath = '.\dist\SentinelForge-Windows.zip',
    [string]$ExpectedSha256 = '',
    [string]$OutputFile = '.\evidence\windows-build-evidence.json'
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
    throw "Release ZIP not found: $ZipPath"
}
$archive = (Resolve-Path -LiteralPath $ZipPath).Path
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToUpperInvariant()
if ($ExpectedSha256 -and $hash -ne $ExpectedSha256.ToUpperInvariant()) {
    throw "SHA256 mismatch: expected $ExpectedSha256; actual $hash"
}

# Python validates ZIP CRCs; checking only the ZIP listing is insufficient.
$verify = "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); want=['SentinelForge.exe','SentinelForgeAgent.exe']; names=sorted(z.namelist()); assert names==sorted(want), 'Unexpected ZIP contents: '+repr(names); corrupt=z.testzip(); assert corrupt is None, 'Corrupt member: '+str(corrupt); print('ZIP contents and CRC: PASS')"
& python -c $verify $archive
if ($LASTEXITCODE -ne 0) { throw 'ZIP contents/CRC verification failed.' }

$temp = Join-Path $env:TEMP ("SentinelForge-Capstone-" + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $temp -Force
    $cli = Join-Path $temp 'SentinelForge.exe'
    $agent = Join-Path $temp 'SentinelForgeAgent.exe'
    if (-not (Test-Path -LiteralPath $cli) -or -not (Test-Path -LiteralPath $agent)) {
        throw 'Expected executables were not extracted.'
    }
    & $cli --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'CLI --help smoke test failed.' }
    & $cli demo | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'CLI synthetic demo smoke test failed.' }

    $entry = [ordered]@{
        status = 'PASS'
        inspected_utc = (Get-Date).ToUniversalTime().ToString('o')
        zip_name = [IO.Path]::GetFileName($archive)
        zip_sha256 = $hash
        zip_bytes = (Get-Item -LiteralPath $archive).Length
        members = @(
            [ordered]@{ name = 'SentinelForge.exe'; bytes = (Get-Item -LiteralPath $cli).Length },
            [ordered]@{ name = 'SentinelForgeAgent.exe'; bytes = (Get-Item -LiteralPath $agent).Length }
        )
        validations = @('zip_members_exact', 'zip_crc', 'cli_help', 'cli_synthetic_demo')
        scope = 'Archive and CLI smoke tests only; NOT real Windows event or SMTP validation.'
    }
    $parent = Split-Path -Parent $OutputFile
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $entry | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
    Write-Host "PASS: ZIP SHA256 $hash"
    Write-Host "Evidence written to $OutputFile"
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Remove-Item -LiteralPath $temp -Recurse -Force
    }
}
