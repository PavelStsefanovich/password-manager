$message_padding = "  "

function error {

    param(
        [string]$message
    )

    Write-Host ($message_padding + "ERROR: $message`n") -ForegroundColor Red
}

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

function warning {

    param(
        [string]$message,
        [switch]$no_newline,
        [switch]$no_prefix
    )

    if ($no_prefix) {
        Write-Host ($message_padding + $message) -ForegroundColor Yellow -NoNewline:$no_newline
    }
    else {
        Write-Host ($message_padding + "WARNING: $message") -ForegroundColor Yellow -NoNewline:$no_newline
    }
}

function confirm {

    param(
        [string]$message,
        [switch]$no_newline
    )

    Write-Host ($message_padding + $message) -ForegroundColor Green -NoNewline:$no_newline
}

function request_consent {

    param(
        [string]$question
    )

    do {
        warning (" (?) $question ( Y: yes / N: no): ") -no_prefix
        $reply = [string]$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
        if ($reply.tolower() -notin 'y', 'n') {
            error "It's a yes/no question."
        }
    }
    while ($reply.tolower() -notin 'y', 'n')

    switch ($reply) {
        'y' { info "<yes>"; return $true }
        'n' { info "<no>"; return $false }
    }
}



##########################################################################

$ErrorActionPreference = 'Stop'
$metadata_file = Join-Path $PSScriptRoot 'install.config'

newline
info "Reading metadata file  : $metadata_file"
$product_name = (sls $metadata_file -Pattern '^name=(\w+)$').Matches.Groups[1].Value
$product_version = (sls $metadata_file -Pattern '^version=([\d\.]+)$').Matches.Groups[1].Value

newline
info "Installing version     : $product_version"
info "Installation directory : $PSScriptRoot"
if (!(request_consent "Proceed?")) {
    warning "Installation cancelled by user."
    newline
    exit
}

newline
info "Installing..."

try {
    $executable_path = (Get-Item "$PSScriptRoot\$product_name`.exe").FullName
}
catch {
    newline
    error "Could not find $product_name`.exe"
    throw $_
}

# create application shortcut
$link_path = Join-Path $env:USERPROFILE "Start Menu\Programs\$product_name`.lnk"
$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($link_path)
$objShortCut.TargetPath = $executable_path
$objShortCut.WorkingDirectory = $PSScriptRoot
$objShortCut.Save()

newline
info "Installation complete"
if (request_consent "Would you like to launch $product_name now?") {
    info "starting application"
    & $executable_path
}

newline
