# Installation Guide

## Prerequisites

- Python 3.9 or higher
- pip package manager

## Windows Installation

```bash
.\install_windows.bat
```

## Linux/macOS Installation

```bash
chmod +x install_linux.sh
./install_linux.sh
```

## Manual Installation

```bash
python3 -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Troubleshooting

### Python not found
Ensure Python 3.9+ is installed and in PATH.

### Dependency installation fails
```bash
python -m pip install --upgrade pip
```
