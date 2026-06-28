@echo off
REM NetSleuth Installation Script for Windows

echo.
echo ======================================
echo NetSleuth - Installation
echo ======================================
echo.

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org
    pause
    exit /b 1
)

echo.
echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ======================================
echo Installation Complete!
echo ======================================
echo.
echo To run NetSleuth, execute: run.bat
echo.
pause
