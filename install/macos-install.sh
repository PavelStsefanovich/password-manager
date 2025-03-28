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

# Retrieve Application Bundle path
APP_BUNDLE_PATH=$(find "$SCRIPT_DIR" -maxdepth 1 -type d -name "*.app")
APP_BUNDLE_NAME=$(echo "${APP_BUNDLE_PATH}"| xargs -I {} basename "{}")
DEST_PATH="/Applications/${APP_BUNDLE_NAME}"

# Move Application bundle to Applications directory
if [ ! -e "${APP_BUNDLE_PATH}" ]; then
    error_exit "Canot find application bundle in directory '${SCRIPT_DIR}'"
fi

info_message "Moving ${APP_BUNDLE_NAME} to Applications folder (sudo password required)..."
if [ -d "$DEST_PATH" ]; then
    sudo rm -rf "$DEST_PATH"
fi

sudo cp -R "$APP_BUNDLE_PATH" "$DEST_PATH"

# Check if the move was successful
if [ $? -eq 0 ]; then
    info_message "${APP_BUNDLE_NAME} has been successfully moved to the Applications folder."
else
    error_exit "Error: Failed to move ${APP_BUNDLE_NAME} to the Applications folder."
fi
