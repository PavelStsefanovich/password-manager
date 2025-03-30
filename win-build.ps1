param (
    [switch] $package
)


$ErrorActionPreference = 'Stop'

# vars
$main_python_script = Join-Path $PSScriptRoot 'main.py'
$app_name = ((Get-Content $main_python_script | Select-String -Pattern 'APP_NAME\s=\s\"([^"]+)\"\s*$').Matches.Groups[1].Value).Trim()
$app_version = ((Get-Content $main_python_script | Select-String -Pattern 'APP_VERSION\s=\s\"([^"]+)\"\s*$').Matches.Groups[1].Value).Trim()
$venv = Join-Path $PSScriptRoot '.venv'
$venv_activate = Join-Path $venv 'Scripts\activate.ps1'
$installation_files = Get-ChildItem (Join-Path $PSScriptRoot 'install\win-*')
$dist_path = Join-Path $PSScriptRoot "dist\$app_name"
$metadata_file = Join-Path $dist_path 'install.config'
$specfile_path = Join-Path $PSScriptRoot "win-build.spec"
$temp_specfile_path = Join-Path $PSScriptRoot "build.spec"
$zipfile_path = Join-Path $PSScriptRoot "dist\$app_name`.zip"
$note_color = "DarkCyan"

Write-Host ":: Building app `"$app_name`", version `"$app_version`" ::" -ForegroundColor $note_color
Start-Sleep 2

Write-Host ":: Activating Virtual Environment ::" -ForegroundColor $note_color
try { deactivate } catch {}
try { . $venv_activate }
catch {
    python -m venv $venv
    . $venv_activate
}

# install dependencies
Write-Host ":: Installing Dependencies ::" -ForegroundColor $note_color
& pip install -r requirements.txt

# build project
Write-Host ":: Parsing -build.spec File ::" -ForegroundColor $note_color
(Get-Content $specfile_path -Raw).Replace('<APP_NAME>', $app_name) | Set-Content $temp_specfile_path

Write-Host ":: Building Project ::" -ForegroundColor $note_color
& pyinstaller $temp_specfile_path
if ( $LASTEXITCODE -ne 0 ) { throw "Build failed!" }

Remove-Item $temp_specfile_path -Force

# Copy install files to dist directory
Copy-Item $installation_files.FullName $dist_path -Recurse -Force
Copy-Item README.md $dist_path -Force
"name=$app_name" | Out-File $metadata_file -Encoding utf8 -Force
"version=$app_version" | Out-File $metadata_file -Encoding utf8 -Force -Append

# create zip package
if ( $package ) {
    Write-Host ":: Creating Zip Package ::" -ForegroundColor $note_color
    Remove-Item $zipfile_path -Force -ErrorAction SilentlyContinue
    Add-Type -AssemblyName "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($dist_path, $zipfile_path, "Optimal", $false)
}

Write-Host "Build process completed successfully!" -ForegroundColor $note_color
