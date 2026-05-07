#Requires -Version 5.1
<#
.SYNOPSIS
    Converts a Royal TS (.rtsz) document into a CyberArk SIA-enabled duplicate,
    preserving the original folder hierarchy.
#>

[CmdletBinding()]
param()

Add-Type -AssemblyName System.Windows.Forms

$ConfigFile = Join-Path $PSScriptRoot 'sia_config.json'

# ---------------------------------------------------------------------------
# Module bootstrapping
# ---------------------------------------------------------------------------

function Invoke-ModuleSetup {
    $moduleName = 'RoyalDocument.PowerShell'
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Host "Installing $moduleName from PSGallery (this only happens once)..." -ForegroundColor Cyan
        try {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
            }
            Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch {
            throw "Could not install ${moduleName}: $_`nTry manually: Install-Module $moduleName -Scope CurrentUser"
        }
    }
    Import-Module $moduleName -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# GUI file dialogs
# ---------------------------------------------------------------------------

function Get-RtszFileGui {
    param([string]$Title, [string]$InitDir)
    $dlg                  = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title            = $Title
    $dlg.Filter           = 'Royal TS Documents (*.rtsz)|*.rtsz|All Files (*.*)|*.*'
    $dlg.InitialDirectory = $InitDir
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
    return $null
}

function Save-RtszFileGui {
    param([string]$Title, [string]$InitDir, [string]$DefaultName)
    $dlg                  = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title            = $Title
    $dlg.Filter           = 'Royal TS Documents (*.rtsz)|*.rtsz|All Files (*.*)|*.*'
    $dlg.InitialDirectory = $InitDir
    $dlg.FileName         = $DefaultName
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
    return $null
}

# ---------------------------------------------------------------------------
# Config persistence (extends shared sia_config.json)
# ---------------------------------------------------------------------------

function Get-Config {
    $myDocs   = [Environment]::GetFolderPath('MyDocuments')
    $defaults = [ordered]@{
        TenantFriendlyName = ''
        IdentityTenantId   = ''
        IspssUsername      = ''
        EnableMfaCache     = $false
        TargetGroupName    = 'CyberArk SIA Connections'
        SourceRdgPath      = $myDocs
        TargetRdgPath      = (Join-Path $myDocs 'SIA_Connections.rdg')
        SourceRtszPath     = $myDocs
        TargetRtszPath     = (Join-Path $myDocs 'SIA_Connections.rtsz')
    }
    if (Test-Path $ConfigFile) {
        $saved = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($key in @($defaults.Keys)) {
            if ($null -ne $saved.$key -and $saved.$key -ne '') {
                $defaults[$key] = $saved.$key
            }
        }
    }
    return $defaults
}

function Save-Config {
    param($Config)
    $Config | ConvertTo-Json | Set-Content $ConfigFile -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Interactive config prompt
# ---------------------------------------------------------------------------

function Read-Value {
    param([string]$Prompt, [string]$Current)
    $hint = if ($Current) { " [$Current]" } else { '' }
    $val  = Read-Host "${Prompt}${hint}"
    if ($val) { return $val } else { return $Current }
}

function Invoke-ConfigPrompt {
    param($Config)

    Write-Host ''
    Write-Host '=== CyberArk SIA Connection Builder (Royal TS) ===' -ForegroundColor Cyan
    Write-Host 'Press Enter to keep the value shown in [brackets].' -ForegroundColor DarkGray
    Write-Host ''

    $Config.TenantFriendlyName = Read-Value 'CyberArk tenant friendly name'   $Config.TenantFriendlyName
    $Config.IspssUsername      = Read-Value 'ISPSS username'                   $Config.IspssUsername

    $mfaHint = if ($Config.EnableMfaCache) { 'Y' } else { 'N' }
    $mfaVal  = Read-Host "Enable MFA caching token (/m flag)? (Y/N) [$mfaHint]"
    if ($mfaVal) { $Config.EnableMfaCache = ($mfaVal -match '^[Yy]') }

    # Source .rtsz file
    Write-Host ''
    $srcHint = if ($Config.SourceRtszPath) { " [$($Config.SourceRtszPath)]" } else { '' }
    Write-Host "Source Royal TS document${srcHint}" -ForegroundColor White
    $srcVal = Read-Host '  Type a path, B to browse, or Enter to keep'
    if (-not $srcVal -and $Config.SourceRtszPath) {
        # keep current
    } elseif (-not $srcVal -or $srcVal -match '^[Bb]$') {
        $initDir = if ($Config.SourceRtszPath -and (Test-Path (Split-Path $Config.SourceRtszPath -Parent))) {
            Split-Path $Config.SourceRtszPath -Parent
        } else { [Environment]::GetFolderPath('MyDocuments') }
        $path = Get-RtszFileGui 'Select source Royal TS document' $initDir
        if ($path) { $Config.SourceRtszPath = $path }
    } else {
        $Config.SourceRtszPath = $srcVal.Trim('"')
    }

    # Target .rtsz file
    Write-Host ''
    $tgtHint = if ($Config.TargetRtszPath) { " [$($Config.TargetRtszPath)]" } else { '' }
    Write-Host "Target Royal TS output document${tgtHint}" -ForegroundColor White
    $tgtVal = Read-Host '  Type a path, B to browse, or Enter to keep'
    if (-not $tgtVal -and $Config.TargetRtszPath) {
        # keep current
    } elseif (-not $tgtVal -or $tgtVal -match '^[Bb]$') {
        $initDir = if ($Config.TargetRtszPath -and (Test-Path (Split-Path $Config.TargetRtszPath -Parent))) {
            Split-Path $Config.TargetRtszPath -Parent
        } else { [Environment]::GetFolderPath('MyDocuments') }
        $defName = if ($Config.TargetRtszPath) { Split-Path $Config.TargetRtszPath -Leaf } else { 'SIA_Connections.rtsz' }
        $path = Save-RtszFileGui 'Save SIA Royal TS document as' $initDir $defName
        if ($path) { $Config.TargetRtszPath = $path }
    } else {
        $tgtVal = $tgtVal.Trim('"')
        if (-not $tgtVal.EndsWith('.rtsz')) { $tgtVal += '.rtsz' }
        $Config.TargetRtszPath = $tgtVal
    }

    return $Config
}

# ---------------------------------------------------------------------------
# Validate config
# ---------------------------------------------------------------------------

function Test-Config {
    param($Config)
    $errs = @()
    if (-not $Config.TenantFriendlyName) { $errs += 'Tenant friendly name is required.' }
    if (-not $Config.IspssUsername)       { $errs += 'ISPSS username is required.' }
    if (-not $Config.SourceRtszPath)      { $errs += 'Source Royal TS document path is required.' }
    elseif (-not (Test-Path $Config.SourceRtszPath)) {
        $errs += "Source Royal TS document not found: $($Config.SourceRtszPath)"
    }
    if (-not $Config.TargetRtszPath)      { $errs += 'Target Royal TS document path is required.' }
    return $errs
}

# ---------------------------------------------------------------------------
# Count RDP connections in a document (for the summary line)
# ---------------------------------------------------------------------------

function ConvertTo-PlainText {
    param([SecureString]$SecureString)
    if (-not $SecureString -or $SecureString.Length -eq 0) { return $null }
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
}

function Get-ConnectionCount {
    param([string]$Path, [SecureString]$Password)
    try {
        $store = New-RoyalStore -UserName "$env:USERDOMAIN\$env:USERNAME"
        $plain = ConvertTo-PlainText $Password
        $doc   = if ($plain) {
            Open-RoyalDocument -FileName $Path -Store $store -Password $plain
        } else {
            Open-RoyalDocument -FileName $Path -Store $store
        }
        $count = @(Get-RoyalObject -Document $doc -Type RoyalRDSConnection).Count
        Close-RoyalDocument -Document $doc | Out-Null
        return $count
    } catch { return 0 }
}

# ---------------------------------------------------------------------------
# Create a single SIA-enabled RDS connection from a source connection
# ---------------------------------------------------------------------------

function New-SiaRdsConnection {
    param(
        $Source,
        $DestFolder,
        [string]$Tenant,
        [string]$IspssUser,
        [bool]$MfaCache,
        [string]$GwCredName
    )

    $username = "secureaccess /i $IspssUser /s $Tenant /a $($Source.URI)"
    if ($MfaCache) { $username += ' /m' }

    $conn = New-RoyalObject -Folder $DestFolder -Type RoyalRDSConnection -Name "$($Source.Name) (SIA)"

    # All SIA connections route through the SIA gateway endpoint
    Set-RoyalObjectValue -Object $conn -Property 'URI' -Value "$Tenant.rdp.cyberark.cloud"

    # Inline connection credentials (the secureaccess command string is the username)
    Set-RoyalObjectValue -Object $conn -Property 'CredentialMode'      -Value 2      # inline
    Set-RoyalObjectValue -Object $conn -Property 'CredentialUsername'   -Value $username
    Set-RoyalObjectValue -Object $conn -Property 'CredentialPassword'   -Value ''
    Set-RoyalObjectValue -Object $conn -Property 'CredentialAutologon'  -Value $true

    # Gateway — reference the shared gateway credential object by name
    Set-RoyalObjectValue -Object $conn -Property 'GatewayHostName'              -Value "$Tenant.rdp.cyberark.cloud"
    Set-RoyalObjectValue -Object $conn -Property 'GatewayServerCredentialMode'  -Value 5     # credential by name
    Set-RoyalObjectValue -Object $conn -Property 'GatewayCredentialName'         -Value $GwCredName

    return $conn
}

# ---------------------------------------------------------------------------
# Recursively mirror a folder, converting all RDS connections to SIA format
# ---------------------------------------------------------------------------

function Copy-FolderToSia {
    param(
        $SrcFolder,
        $DstFolder,
        [string]$Tenant,
        [string]$IspssUser,
        [bool]$MfaCache,
        [string]$GwCredName
    )

    foreach ($child in @(Get-RoyalObject -Folder $SrcFolder)) {
        switch ($child.GetType().Name) {
            'RoyalFolder' {
                $newFolder = New-RoyalObject -Folder $DstFolder -Type RoyalFolder -Name $child.Name
                Copy-FolderToSia -SrcFolder $child -DstFolder $newFolder `
                    -Tenant $Tenant -IspssUser $IspssUser -MfaCache $MfaCache -GwCredName $GwCredName
            }
            'RoyalRDSConnection' {
                New-SiaRdsConnection -Source $child -DestFolder $DstFolder `
                    -Tenant $Tenant -IspssUser $IspssUser -MfaCache $MfaCache -GwCredName $GwCredName | Out-Null
            }
            # All other types (SSH, web, etc.) are skipped for now
        }
    }
}

# ---------------------------------------------------------------------------
# Main transform: source .rtsz -> new SIA .rtsz
# ---------------------------------------------------------------------------

function New-SiaRtszFile {
    param(
        [string]$SourcePath,
        [string]$TargetPath,
        [string]$Tenant,
        [string]$IspssUser,
        [bool]$MfaCache,
        [SecureString]$SourcePassword,
        [SecureString]$OutputPassword
    )

    $docName  = [System.IO.Path]::GetFileNameWithoutExtension($TargetPath)
    $store    = New-RoyalStore -UserName "$env:USERDOMAIN\$env:USERNAME"
    $srcDoc   = $null
    $outDoc   = $null
    $srcPlain = ConvertTo-PlainText $SourcePassword
    $outPlain = ConvertTo-PlainText $OutputPassword

    try {
        $srcDoc = if ($srcPlain) {
            Open-RoyalDocument -FileName $SourcePath -Store $store -Password $srcPlain
        } else {
            Open-RoyalDocument -FileName $SourcePath -Store $store
        }
        $outDoc = New-RoyalDocument -Name $docName -FileName $TargetPath -Store $store
        if ($outPlain) {
            Set-RoyalDocumentPassword -Document $outDoc -Password $outPlain
        }

        # Shared gateway credential — one per document, referenced by all connections.
        # The gateway always authenticates as secureaccess@cyberark with password secureaccess.
        $gwCredName = "SIA_GW_$Tenant"
        $gwCred = New-RoyalObject -Folder $outDoc -Type RoyalCredential -Name $gwCredName
        Set-RoyalObjectValue -Object $gwCred -Property 'UserName' -Value 'secureaccess@cyberark'
        Set-RoyalObjectValue -Object $gwCred -Property 'Password' -Value 'secureaccess'

        # Mirror top-level folders and any root-level connections from the source
        foreach ($child in @(Get-RoyalObject -Folder $srcDoc)) {
            switch ($child.GetType().Name) {
                'RoyalFolder' {
                    $newFolder = New-RoyalObject -Folder $outDoc -Type RoyalFolder -Name $child.Name
                    Copy-FolderToSia -SrcFolder $child -DstFolder $newFolder `
                        -Tenant $Tenant -IspssUser $IspssUser -MfaCache $MfaCache -GwCredName $gwCredName
                }
                'RoyalRDSConnection' {
                    New-SiaRdsConnection -Source $child -DestFolder $outDoc `
                        -Tenant $Tenant -IspssUser $IspssUser -MfaCache $MfaCache -GwCredName $gwCredName | Out-Null
                }
            }
        }

        Out-RoyalDocument -Document $outDoc
    } finally {
        if ($outDoc) { Close-RoyalDocument -Document $outDoc | Out-Null }
        if ($srcDoc) { Close-RoyalDocument -Document $srcDoc | Out-Null }
    }
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

function Invoke-SIAnableRoyalTS {
    Invoke-ModuleSetup

    $config = Get-Config
    $config = Invoke-ConfigPrompt $config

    $errors = Test-Config $config
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-Host 'Cannot proceed — missing or invalid settings:' -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  • $_" -ForegroundColor Red }
        exit 1
    }

    Save-Config $config

    # Passwords are never saved to config
    Write-Host ''
    Write-Host 'Source document password (press Enter if not encrypted):' -ForegroundColor White
    $srcPassword = Read-Host '  Password' -AsSecureString

    Write-Host ''
    Write-Host 'Encrypt output document? Enter a password or press Enter to skip:' -ForegroundColor White
    $outPassword = Read-Host '  Password' -AsSecureString

    $connCount = Get-ConnectionCount -Path $config.SourceRtszPath -Password $srcPassword

    Write-Host ''
    Write-Host '--- Summary ---' -ForegroundColor Cyan
    Write-Host "  Source file    : $($config.SourceRtszPath) ($connCount RDP connection(s) found)"
    Write-Host "  Output file    : $($config.TargetRtszPath)"
    Write-Host "  Tenant         : $($config.TenantFriendlyName)  →  $($config.TenantFriendlyName).rdp.cyberark.cloud"
    Write-Host "  ISPSS user     : $($config.IspssUsername)"
    Write-Host "  MFA cache (/m) : $($config.EnableMfaCache)"
    Write-Host ''

    $confirm = Read-Host 'Proceed? (Y/N) [Y]'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host 'Building SIA Royal TS document...' -ForegroundColor Cyan

    try {
        New-SiaRtszFile `
            -SourcePath      $config.SourceRtszPath `
            -TargetPath      $config.TargetRtszPath `
            -Tenant          $config.TenantFriendlyName `
            -IspssUser       $config.IspssUsername `
            -MfaCache        $config.EnableMfaCache `
            -SourcePassword  $srcPassword `
            -OutputPassword  $outPassword

        Write-Host "Done. Output written to: $($config.TargetRtszPath)" -ForegroundColor Green
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIAnableRoyalTS
}
