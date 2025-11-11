@echo off
setlocal EnableExtensions

rem Change to project root (this script is in scripts\)
cd /d "%~dp0.." || goto :error

echo === Creating/activating venv ===
if not exist .venv\Scripts\python.exe (
  python -m venv .venv || goto :error
)
call .venv\Scripts\activate || goto :error

echo === Installing dependencies ===
python -m pip install -U pip wheel || goto :error
pip install pyinstaller || goto :error

echo === Building single-file EXE (PyInstaller) ===
pyinstaller --noconsole --onefile --name HavenTFTP --paths src --add-data "assets;assets" scripts\launcher.py || goto :error

echo.
echo Build complete: dist\HavenTFTP.exe
exit /b 0

:error
echo.
echo Build failed. See messages above.
exit /b 1
