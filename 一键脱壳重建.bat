@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONDONTWRITEBYTECODE=1
echo 正在从 bk\crackme.exe 从零提取原料并重建可运行程序...
echo.
python "%~dp0run_all.py" --from-scratch --verify --with-scene %*
set RC=%ERRORLEVEL%
echo.
if %RC% NEQ 0 echo Build failed with code %RC%.
pause >nul
