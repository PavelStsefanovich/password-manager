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
METADATA_FILE="${SCRIPT_DIR}/install.config"
source "$METADATA_FILE"
APP_NAME=$name
APP_VERSION=$version
APP_BUNDLE_NAME="$APP_NAME.app"
APP_BUNDLE_PATH="$SCRIPT_DIR/$APP_BUNDLE_NAME"
DEST_PATH="/Applications/${APP_BUNDLE_NAME}"

info_message "Installing \"$APP_NAME\", version \"$APP_VERSION\""
while true; do
    read -p "Do you want to proceed? (y/n): " answer

    # Convert to lowercase manually for compatibility
    answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')

    case $answer in
        y)
            # Move Application bundle to Applications directory
            if [ ! -e "${APP_BUNDLE_PATH}" ]; then
                error_exit "Application bundle \"$APP_BUNDLE_PATH\" does not exist."
            fi

            info_message "Copying ${APP_BUNDLE_NAME} to Applications folder (sudo password required)..."
            if [ -d "$DEST_PATH" ]; then
                sudo rm -rf "$DEST_PATH"
            fi

            sudo cp -R "$APP_BUNDLE_PATH" "$DEST_PATH"

            # Check if the move was successful
            if [ $? -eq 0 ]; then
                info_message "${APP_BUNDLE_NAME} has been copied to the Applications folder."
            else
                error_exit "Error: Failed to move ${APP_BUNDLE_NAME} to the Applications folder."
            fi

            info_message "Installation of $APP_NAME $APP_VERSION completed successfully."
            break
            ;;
        n)
            info_message "Cancelled by user."
            exit 0
            ;;
        *)
            info_message "Please enter 'y' or 'n'"
            ;;
    esac
done
