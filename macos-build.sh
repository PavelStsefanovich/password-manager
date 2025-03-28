#!/bin/bash

# ANSI Color Codes
DARKCYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored info message
info_message() {
    echo -e "${DARKCYAN}$1${NC}"
}

# Function to print colored error and exit
error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Set error handling
set -e

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script's directory
cd "$SCRIPT_DIR"

# Deactivate any active virtual environment
if [ -n "$VIRTUAL_ENV" ]; then
    info_message "Deactivating current virtual environment..."
    deactivate
fi

# Check for existing virtual environment
VENV_PATH=".venv"

# Attempt to activate existing virtual environment
if [ -d "$VENV_PATH" ]; then
    info_message "Attempting to activate existing virtual environment..."
    source "$VENV_PATH/bin/activate" || error_exit "Failed to activate existing virtual environment"
else
    # Create new virtual environment
    info_message "Creating new virtual environment..."
    python3 -m venv "$VENV_PATH" || error_exit "Failed to create virtual environment"
    
    # Activate the new virtual environment
    source "$VENV_PATH/bin/activate" || error_exit "Failed to activate new virtual environment"
    
    # Install dependencies
    info_message "Installing dependencies..."
    pip install -r requirements.txt || error_exit "Failed to install dependencies"
fi

# Ensure PyInstaller is installed
# info_message "Ensuring PyInstaller is installed..."
# pip install pyinstaller || error_exit "Failed to install PyInstaller"

# Build the application
info_message "Building application with PyInstaller..."
pyinstaller macos-build.spec || error_exit "PyInstaller build failed"

# Create versioned distribution directory
DIST_DIR="dist/SimplePasswordManager.v1.0"
info_message "Creating distribution directory..."
mkdir -p "$DIST_DIR" || error_exit "Failed to create distribution directory"

# Copy install files to distribution directory
info_message "Copying install files..."
cp -R install/* "$DIST_DIR/" || error_exit "Failed to copy install files"

info_message "Build process completed successfully!"

# Optional: Deactivate virtual environment after build
# deactivate