# Publication-ready description (accurate at current test status)

**SentinelForge — Local Windows Security Event Monitoring & Email Alerting (Research Prototype)**

Built a Windows security monitoring prototype that collects selected Windows Security, System, and Microsoft Defender event records; applies rule-based detections and failed-logon burst correlation; persists alert/outbox state in SQLite; and delivers Gmail notifications using credentials stored in Windows Credential Manager. Packaged a background agent and a command-line interface for Windows, with a repeatable build script and tests. Added a synthetic end-to-end delivery self-test and a RecordID-aware oldest-first collection strategy to reduce missed records under capped polling. Documented trust boundaries, failure modes, and an experimental protocol for quantifying detection fidelity and latency.

**Evidence:** 14 automated tests passed in a development environment. Previous installation delivered live test Gmail alerts, but the current release candidate still needs fresh-Windows validation and controlled performance measurements.
