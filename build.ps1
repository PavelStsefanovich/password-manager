param (
    [switch] $package
)


# vars
$version = "1.0"
$venv = Join-Path $pwd.path 'venv'
$venv_activate = Join-Path $venv 'Scripts\activate'
$dist_path = Join-Path $pwd.path 'dist\SimplePasswordManager'
$resources_path = Join-Path $dist_path '_internal\resources'
$specfile_path = Join-Path $pwd.path 'SimplePasswordManager.spec'
$zipfile_path = Join-Path $pwd.path "SimplePasswordManager.v$version`.zip"
$note_color = "DarkCyan"

Write-Host ":: Activating Virtual Environment ::" -ForegroundColor $note_color

# deactivate any active virtual environment
try { & deactivate } catch {}

# activate virtual environment, create if needed
try { & $venv_activate } catch {}

if ( $env:VIRTUAL_ENV -ne $venv ) {
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

# copy resources files
Copy-Item $resources_path $dist_path -Recurse -Force

# bundle up
if ( $package ) {
    Write-Host ":: Creating Zip Package ::" -ForegroundColor $note_color
    Remove-Item $zipfile_path -Force -ErrorAction SilentlyContinue
    Add-Type -AssemblyName "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($dist_path, $zipfile_path, "Optimal", $false)
}
