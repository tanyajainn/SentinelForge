$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Regression tests failed. Nothing packaged.' }

python -m pip install pyinstaller keyring
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }

python -m PyInstaller --noconfirm --clean --onefile --console --name SentinelForge --paths . --collect-submodules sentinelforge --collect-submodules keyring --hidden-import dashboard --hidden-import keyring.backends.Windows .\sentinelforge_entry.py
if ($LASTEXITCODE -ne 0) { throw 'CLI build failed.' }

python -m PyInstaller --noconfirm --clean --onefile --noconsole --name SentinelForgeAgent --paths . --collect-submodules sentinelforge --collect-submodules keyring --hidden-import dashboard --hidden-import keyring.backends.Windows .\sentinelforge_agent_entry.py
if ($LASTEXITCODE -ne 0) { throw 'Agent build failed.' }

& .\dist\SentinelForge.exe --help
if ($LASTEXITCODE -ne 0) { throw 'CLI smoke test failed.' }
& .\dist\SentinelForge.exe demo
if ($LASTEXITCODE -ne 0) { throw 'Detection smoke test failed.' }

Compress-Archive -Path .\dist\SentinelForge.exe,.\dist\SentinelForgeAgent.exe -DestinationPath .\dist\SentinelForge-Windows.zip -Force
Write-Host 'Release build and smoke tests passed. dist\SentinelForge-Windows.zip' -ForegroundColor Green

