param (
    [switch] $package
)

$ErrorActionPreference = 'Stop'

# vars
$name = "SimplePasswordManager"
$version = "1.0"
$venv = Join-Path $PSScriptRoot 'venv'
$venv_activate = Join-Path $venv 'Scripts\activate'
$installation_files = Get-ChildItem (Join-Path $PSScriptRoot 'install')
$dist_path = Join-Path $PSScriptRoot "dist\$name"
$resources_path = Join-Path $dist_path '_internal\resources'
$metadata_file = Join-Path $dist_path 'metadata.config'
$specfile_path = Join-Path $PSScriptRoot "$name`.spec"
$zipfile_path = Join-Path $PSScriptRoot "$name`.v$version`.zip"
$note_color = "DarkCyan"

Write-Host ":: Activating Virtual Environment ::" -ForegroundColor $note_color

# deactivate any active virtual environment
try { & deactivate } catch {}

# activate virtual environment, create if needed
try { & $venv_activate } catch { Remove-Item Env:\VIRTUAL_ENV }

if ( ! $env:VIRTUAL_ENV ) {
    & python -m venv venv
    & .\venv\Scripts\activate
}

if ( $env:VIRTUAL_ENV -ne $venv ) { throw "Failed to activate virtual environment." }

# install dependencies
Write-Host ":: Installing Dependencies ::" -ForegroundColor $note_color
& pip install -r requirements.txt

# build project
Write-Host ":: Building Project ::" -ForegroundColor $note_color
& pyinstaller $specfile_path
if ( $LASTEXITCODE -ne 0 ) { throw "Build failed!" }

# bundle up
Copy-Item $resources_path $dist_path -Recurse -Force
Copy-Item $installation_files.FullName $dist_path -Recurse -Force
"name=$name" | Out-File $metadata_file -Encoding utf8 -Force
"version=$version" | Out-File $metadata_file -Encoding utf8 -Force -Append

# create zip package
if ( $package ) {
    Write-Host ":: Creating Zip Package ::" -ForegroundColor $note_color
    Remove-Item $zipfile_path -Force -ErrorAction SilentlyContinue
    Add-Type -AssemblyName "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($dist_path, $zipfile_path, "Optimal", $false)
}
