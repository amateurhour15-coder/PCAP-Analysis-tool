#!/bin/bash

# NetSleuth Installation Script for Linux/macOS

echo ""
echo "======================================"
echo "NetSleuth - Installation"
echo "======================================"
echo ""

# Check Python
echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Please install Python 3.9+ using your package manager"
    exit 1
fi

python3 --version

# Create venv
echo ""
echo "Creating virtual environment..."
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create virtual environment"
    exit 1
fi

# Activate venv
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

echo ""
echo "======================================"
echo "Installation Complete!"
echo "======================================"
echo ""
echo "To run NetSleuth, execute: ./run.sh"
echo ""
