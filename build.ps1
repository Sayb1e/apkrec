# 构建独立可执行文件（Windows）
# 用法:  powershell -ExecutionPolicy Bypass -File .\build.ps1
# 产物:  dist\apkrec.exe（命令行）、dist\apkrec-gui.exe（图形界面）

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

python -m pip install --upgrade pyinstaller
if ($LASTEXITCODE -ne 0) { throw 'pyinstaller 安装失败' }

python -m PyInstaller --noconfirm --clean --onefile --console  --name apkrec     apkrec.py
python -m PyInstaller --noconfirm --clean --onefile --windowed --name apkrec-gui apkrec_gui.py

if ($LASTEXITCODE -ne 0) { throw '打包失败' }
Get-ChildItem .\dist\*.exe | Select-Object Name, @{n='MB'; e={[math]::Round($_.Length/1MB,2)}}
Write-Host '完成: dist\apkrec.exe / dist\apkrec-gui.exe'
