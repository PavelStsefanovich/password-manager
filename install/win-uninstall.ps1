$message_padding = "  "

function info {

    param(
        [string]$message,
        [switch]$no_newline
    )

    Write-Host ($message_padding + $message) -ForegroundColor Gray -NoNewline:$no_newline
}

function newline {

    param(
        [int]$count = 1
    )

    Write-Host ("$message_padding`n" * $count).TrimEnd()
}



##########################################################################

$ErrorActionPreference = 'Stop'
$metadata_file = Join-Path $PSScriptRoot 'install.config'

newline
info "Reading metadata file  : $metadata_file"
$product_name = (sls $metadata_file -Pattern '^name=(\w+)$').Matches.Groups[1].Value
# $product_version = (sls $metadata_file -Pattern '^version=([\d\.]+)$').Matches.Groups[1].Value

info "Uninstalling..."
$link_path = Join-Path $env:USERPROFILE "Start Menu\Programs\$product_name`.lnk"
Remove-Item $link_path -Force -ErrorAction SilentlyContinue
$config_path = Join-Path $env:USERPROFILE "AppData\Local\$product_name"
Remove-Item $config_path -Force -Recurse -ErrorAction SilentlyContinue

info "Uninstall complete"
newline
