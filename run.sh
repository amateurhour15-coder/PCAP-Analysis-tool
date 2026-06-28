#!/bin/bash

# NetSleuth Run Script for Linux/macOS

if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run ./install_linux.sh first."
    exit 1
fi

source venv/bin/activate
python netsleuth.py
