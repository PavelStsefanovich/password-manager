#!/usr/bin/env bash

# Bash-specific shell options
shopt -s nullglob  # Allow null globs
set -o pipefail   # Catch failures in piped commands
set -e            # Exit immediately on error
set -u            # Treat unset variables as an error

# ANSI Color Codes
DARKCYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored info message
info_message() {
    printf "${DARKCYAN}%s${NC}\n" "$1"
}

# Function to print colored error and exit
error_exit() {
    printf "${RED}Error: %s${NC}\n" "$1" >&2
    exit 1
}

# Get the directory of the script (Bash-specific method)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script's directory
cd "$SCRIPT_DIR" || error_exit "Unable to change to script directory"

# Deactivate any active virtual environment
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    info_message "Deactivating current virtual environment..."
    deactivate
fi

# Check for existing virtual environment
VENV_PATH=".venv"

# Attempt to activate existing virtual environment
if [[ -d "$VENV_PATH" ]]; then
    info_message "Attempting to activate existing virtual environment..."
    # shellcheck source=/dev/null
    source "$VENV_PATH/bin/activate" || error_exit "Failed to activate existing virtual environment"
else
    # Create new virtual environment
    info_message "Creating new virtual environment..."
    python3 -m venv "$VENV_PATH" || error_exit "Failed to create virtual environment"
    
    # Activate the new virtual environment
    # shellcheck source=/dev/null
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