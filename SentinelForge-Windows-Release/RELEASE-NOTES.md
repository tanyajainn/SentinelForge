# SentinelForge Windows Research Release

## Installation

1. Extract the ZIP.
2. Open PowerShell as Administrator under your own account.
3. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-SentinelForge.ps1
```

4. Configure Gmail using a valid Gmail App Password.
5. Open a new PowerShell window.
6. Type `SentinelForge`.

## Features

- Windows Security, System and Defender event monitoring
- Automatic background monitoring at Windows login
- SQLite alert storage and email notification queue
- Free Gmail SMTP notification support
- Windows Credential Manager credential storage
- Persistent SMTP retry cooldown
- One-word PowerShell command

## Limitations

SentinelForge detects selected security events, not every threat.
It does not replace Microsoft Defender or an EDR.
Gmail delivery depends on Google service availability and limits.
The installer needs administrator approval.
Monitoring begins at user login.
Clean-install and long-duration reliability tests are outstanding.

## Research

This is a cybersecurity research release candidate.
A masters-level claim requires reproducible experiments,
detection metrics, false-positive analysis and measured results.

License: MIT. See LICENSE.
