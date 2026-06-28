@echo off
REM NetSleuth Run Script for Windows

if not exist "venv" (
    echo Virtual environment not found. Please run install_windows.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
python netsleuth.py
pause
