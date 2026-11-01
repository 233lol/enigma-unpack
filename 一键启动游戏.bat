@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
python "%~dp0enigma_launch.py" %*
set RC=%ERRORLEVEL%
if %RC% GEQ 4 (
  echo.
  echo Launch failed with code %RC%. Press any key to close.
  pause >nul
)
