# SentinelForge — Security Validation

## Overview

SentinelForge is an independently developed Windows
endpoint security monitoring and threat analysis project.

This directory contains reproducible validation artifacts
for the experimental unified detection engine.

## Components

- Authentication detection comparison
- Multi-signal security analysis output
- Automated regression test results
- Detection performance documentation

## Synthetic Evaluation

| Metric | V1 | V2 |
|---|---:|---:|
| Precision | 60.0% | 65.7% |
| Recall | 50.0% | 63.9% |
| F1 Score | 54.5% | 64.8% |

These measurements come from 72 synthetic episodes.
They do not establish real-world detection accuracy.

## Development Status

The unified detection engine is experimental.

Planned development includes:

- Live endpoint telemetry integration
- Behavioral event correlation
- Multi-endpoint monitoring
- Independent detection validation
- Approval-controlled incident response

## Safety

No automatic firewall modifications.
No production deployment is implied.
No malware execution is required for validation.
