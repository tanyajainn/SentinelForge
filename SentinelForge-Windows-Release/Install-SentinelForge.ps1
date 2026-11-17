# SentinelForge historical installer retired for safety (SF-01).
# The original version ran an elevated scheduled task from a user-writable
# LOCALAPPDATA directory. Never reinstate Highest + user-writable executables.
$ErrorActionPreference = 'Stop'
throw 'This historical SentinelForge installer is retired for security reasons. Existing installations are untouched. Use a separately verified protected installer when available.'
