# Password Manager

> Simple password manager that stores secrets locally on your computer.

The app does not access public Internet in any way, so it's up to you to sync your secrets across devices. One option is to use one of the cloud storage providers that automatically syncs specific files on your computer, such as Google Drive or OneDrive. The secret data is encrypted at rest and can only be decrypted with master password.

## Build From Source
The whole idea behind this project is to have absolute visibility into how the app is handling your sensitive data - so called zero trust approach. Therefore, I provided build scripts for each of the target platforms (Windows, MacOS, Linux), that should allow you to easily build the app directly from the source code, rather than use pre-packaged bundles or binaries.

Building from source also reduces the chances of incompatibility with your specific system.

### Windows
```powershell
# navigate to the project root directory (update path as needed)
cd <project_root>
# run build script
.\win-build.ps1
# run installation script (update path as needed)
.\dist\SimplePasswordManager\win-install.ps1
```

### MacOS
```powershell
# navigate to the project root directory (update path as needed)
cd <project_root>
# run build script
bash macos-build.sh
# run installation script (update path as needed)
bash dist/package/SimplePasswordManager/macos-install.sh
```

### Linux
```powershell
# navigate to the project root directory (update path as needed)
cd <project_root>
# run build script
bash linux-build.sh
# run installation script (update path as needed)
bash dist/SimplePasswordManager/linux-install.sh
```
> NOTE: Linux flows (build/install/uninstall/runtime) have not been tested.


## Download Pre-built Package
If you prefer to use pre-built package, please follow these steps:

1. Download a zip package for your platform from [password-manager/releases](https://github.com/PavelStsefanovich/password-manager/releases) page

2. Extract files from zip package:
   + On Windows: extraction directory will be used as installation directory.
   + On MacOS: extraction directory is temporary, files can be extracted anywhere
   + On Linux: you guys usually have your own ways, so do what you want

3. Run installation script inside the extraction directory
   ```powershell
   # navigate to the extraction directory
   cd <extraction_dir>

   # Windows
   .\win-install.ps1

   # MacOS
   bash macos-install.sh

   # Linux
   bash macos-install.sh
   ```
   > NOTE: On Mac OS you will be prompted to enter your `sudo` password (most likely the one you use to log in to your Mac). You can also manually move SimplePasswordManager.app bundle into your `/Applications` directory.

## How To USE
- On the first run you will be prompted to create a new vault. The vault must have `.db` extension.
- If you did not immediately create the vault, you can do it later from the `File` menu.
- You can choose location for your vault that is monitored by the cloud storage clent, such as Google Drive or OneDrive to have it synced across your devices (you will need to install the Password Manager app on each of your devices).
- You can create more than one vault and switch between them. The vault that you used the last will be selected next time that you open the app.

## Upgrade
Upgrade process is pretty sraight forward:

### Windows
1. Download new pre-build package or re-build from source with *-package* option to create a zip file (dont forget to run `git pull` first).
2. Extract the zip package into the exiting installation directory and choose to overwrite with new files (if you instaled directly from `dist` directory, you dont even need to package new zip, just rebuild).
3. You should be good to go. There is no need to run install script, unless you change the installation directory.

### MacOS
1. Download pre-built package, or re-build from source (dont forget to run `git pull` first)
2. Run `bash macos-install.sh` script from package directory (such as `./package/SimplePasswordManager`), or just manually move SimplePasswordManager.app into /Applications directory.

# Lastly
If you experience any issues, I will be happy to hear about them, but please dont expect me to fix them immediately, as I do not actively maintain this project. You have the source, feel free to tune it to your needs.

Have fun and stay safe!
