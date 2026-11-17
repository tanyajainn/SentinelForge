# Batch 7: Windows preflight and release integrity

This batch **does not perform upgrades** or change the installed task. It adds a
read-only inspection gate and artifact hash verification. Both are prerequisites
for a later tested rollback-capable installer.

## Release artifacts

Build both executables using `build-windows.ps1` in a clean Windows build environment.
Then, from the repository root, run:

```powershell
python -m sentinelforge.release_guard create --folder dist
python -m sentinelforge.release_guard verify --folder dist
```

Keep `dist/SentinelForge-checksums.json` alongside the artifacts. This verifies
consistency, **not authenticity**; a trusted source, signing and provenance are
still needed. Never accept hashes from an untrusted artifact source as proof
of publisher identity.

## Read-only installed task preflight

From a normal PowerShell session with permissions to inspect the task:

```powershell
& .\scripts\Test-SentinelForgeUpgrade.ps1 -BuildDirectory .\dist
if ($LASTEXITCODE -ne 0) { throw 'Upgrade preflight failed; no installation changes authorized' }
```

The output is JSON with `passed`, `issues`, `warnings`, and installed/build
executable hashes. It checks for recognized protected Program Files locations,
Limited/Interactive scheduled task identity, unexpected arguments, file
existence, reparse points, owner and weak writable ACLs. The ACL check is
**conservative and not exhaustive** (nested groups and all effective-access
conditions need further review). Unsigned test builds generate warnings.

### Before a real upgrade

- Make an independent backup of the existing SQLite database (using SQLite's
  supported backup mechanism), config, and task XML; preserve access rights.
- Inspect signatures, release provenance and new executable checksums.
- Verify the task principal SID matches the intended owner, not just name.
- Test the proposed executable in an isolated Windows VM.
- Test failed update rollback and ensure old task action can be restored.
- Only then implement and exercise an **explicitly approved upgrade process**.

**Do not run `update-installed.ps1` as part of this preflight.** It changes
scheduled task definitions and currently lacks comprehensive rollback handling.
