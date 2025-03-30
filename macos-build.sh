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

# Function to print usage information
usage() {
    echo "Usage: $0 [-p] "
    echo "  -p    Package the build into a zip archive"
    exit 1
}

# Parse command-line arguments
PACKAGE_FLAG=false
while getopts ":p" opt; do
    case ${opt} in
        p )
            PACKAGE_FLAG=true
            ;;
        \? )
            usage
            ;;
    esac
done
shift $((OPTIND -1))

# Function to print colored info message
info_message() {
    printf "${DARKCYAN}%s${NC}\n" "$1"
}

# Function to print colored error and exit
error_exit() {
    printf "${RED}Error: %s${NC}\n" "$1" >&2
    exit 1
}



# Vars
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR" || error_exit "Unable to change to script directory"

# Extract version from main.py
APP_NAME=$(grep 'APP_NAME' main.py | head -n1 | sed -E 's/.*APP_NAME = "([^"]+)".*/\1/')
VERSION=$(grep 'APP_VERSION' main.py | head -n1 | sed -E 's/.*APP_VERSION = "([^"]+)".*/\1/')

# Validate version extraction
if [[ -z "$VERSION" ]]; then
    error_exit "${RED}Error: Could not extract version from main.py${NC}\n" >&2
fi

PACKAGE_DIR="dist/package/${APP_NAME}"
ZIP_FILE="dist/package/${APP_NAME}.zip"
METADATA_FILE="$PACKAGE_DIR/install.config"
BUILD_SPEC_FILE="${SCRIPT_DIR}/macos-build.spec"
BUILD_SPEC_FILE_TEMP="${SCRIPT_DIR}/build.spec"
VENV_PATH=".venv"

info_message "Building app \"$APP_NAME\", version \"$VERSION\""
sleep 2

# Remove distribution directory and zipfile if exist from prevous build
if [[ -d "$PACKAGE_DIR" ]]; then
    info_message "Removing existing distribution directory..."
    rm -rf "$PACKAGE_DIR"
fi

if [[ -f "$ZIP_FILE" ]]; then
    info_message "Removing existing zip file..."
    rm -rf "$ZIP_FILE"
fi

# Deactivate any active virtual environment
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    info_message "Deactivating current virtual environment..."
    deactivate
fi

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

# Build the application
info_message "Parsing build.spec file..."
awk -v app_name="$APP_NAME" '{gsub(/<APP_NAME>/, app_name)}1' "${BUILD_SPEC_FILE}" > "${BUILD_SPEC_FILE_TEMP}"

info_message "Building application with PyInstaller..."
pyinstaller "${BUILD_SPEC_FILE_TEMP}" || error_exit "PyInstaller build failed"

rm "${BUILD_SPEC_FILE_TEMP}"

# Create versioned package directory
info_message "Creating package directory..."
mkdir -p "$PACKAGE_DIR" || error_exit "Failed to create package directory"

# Copy install files to package directory
info_message "Copying install files..."
cp -R install/macos-* "$PACKAGE_DIR/" || error_exit "Failed to copy install files"
cp README.md "$PACKAGE_DIR/" || error_exit "Failed to copy install files"
echo "name=$APP_NAME" > "$METADATA_FILE"
echo "version=$VERSION" >> "$METADATA_FILE"

# Copy .app directory to package directory
info_message "Copying application bundle..."
cp -R "dist/${APP_NAME}.app" "$PACKAGE_DIR/" || error_exit "Failed to copy application bundle"

# Optional packaging
if [[ "$PACKAGE_FLAG" = true ]]; then
    info_message "Creating zip archive..."
    (zip -r "${ZIP_FILE}" "${PACKAGE_DIR}") || \
        error_exit "Failed to create zip archive"
    info_message "Zip archive created: ${ZIP_FILE}"
fi

info_message "Build process completed successfully!"
