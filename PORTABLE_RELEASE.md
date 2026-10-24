# SentinelForge Windows portable release (candidate)

This is the **source/build kit**, not a precompiled Windows binary. It requires Windows and Python to **build**; end users do not need Python.

## Build on Windows

In PowerShell, from this folder:

```powershell
.\build-windows.ps1
```

The resulting `dist\SentinelForge-Windows.zip` contains two executables. Extract **both into the same directory** on a Windows laptop.

## Install on a Windows laptop

```powershell
.\SentinelForge.exe setup
```

Setup prompts for the recipient address, Gmail sender, and Gmail App Password. The password is hidden on input and stored via the Windows Credential Manager backend; it is **not embedded in the binaries, task, or config**. Create an App Password in your own Google account (Google account requirements apply). Setup copies both binaries to `%LOCALAPPDATA%\SentinelForge\bin`, registers an at-logon Scheduled Task for the current user, and starts it. The agent polls event logs approximately every 10 seconds *after each scan completes*, then emails eligible new alerts. Closing the terminal does not stop the task.

```powershell
.\SentinelForge.exe status
.\SentinelForge.exe start
.\SentinelForge.exe stop
.\SentinelForge.exe uninstall
```

**Important:** `uninstall` removes the Scheduled Task but deliberately preserves stored alerts and credentials; remove those separately if desired. For status/stop/start from any directory, use the installed binary at `%LOCALAPPDATA%\SentinelForge\bin\SentinelForge.exe`.

## Limitations and testing

- Windows only; designed for Windows 10/11. Some Security log events require elevated permissions or enabled auditing. Task registration may need permissions depending on local policy.
- Not an antivirus, firewall, or guarantee against compromise; it monitors a limited set of Windows Event IDs and sends alerts when detection rules match.
- It runs while Windows and the logged-on user task are active, not when the laptop is powered off.
- The app's `status` command reports Scheduled Task state, not proof that email delivery works; test a benign detection and review `SentinelForgeData\monitor.log` and mailbox.
- Do not run this new setup on the developer laptop until the existing `SentinelForge Security Monitor` task is intentionally migrated: both use the same task name, and setup **replaces** it.
- The package was code-checked and tested in a non-Windows environment; Windows build and installer integration require verification on an actual Windows machine before public distribution.
