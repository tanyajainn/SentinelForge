# SentinelForge v1.0.0 — Research Preview

## Features

- One-word SentinelForge CLI after installation
- Windows Security, System and Defender event monitoring
- Background Windows Task Scheduler monitoring
- SQLite alert storage
- Gmail SMTP notifications
- Windows Credential Manager integration
- Email retry handling
- Automated Python regression tests
- MIT-licensed source code

## Validation evidence

The development installation has demonstrated:
- Working one-word CLI
- Running background monitoring task
- Access to monitored Windows event channels
- Successful Gmail notification delivery
- Passing automated regression tests

## Known limitations

- Fresh Windows installation has not been independently tested.
- Automatic recovery across repeated reboots is not fully measured.
- No guarantee of continuous operation or email delivery.
- Detection accuracy and false-positive rates are not yet measured.
- This is research-preview software, not a commercial security product.

## Installation

Extract all files from SentinelForge-Windows-Release.zip.

Run Install-SentinelForge.ps1 using an elevated PowerShell session
under the intended Windows user account.

Follow the Gmail setup prompts.

Open a new PowerShell session and run:

SentinelForge

The background monitor is configured for Windows login.

## License

MIT License.
