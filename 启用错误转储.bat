@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo 需要管理员权限。正在尝试提权...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)
python "%~dp0extract\enable_dumps.py" %*
echo.
pause >nul
