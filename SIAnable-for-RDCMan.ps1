#Requires -Version 5.1
<#
.SYNOPSIS
    Converts an RDC Manager (.rdg) file into a CyberArk SIA-enabled duplicate,
    preserving the original group hierarchy.
#>

[CmdletBinding()]
param()

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

$ConfigFile = Join-Path $PSScriptRoot 'sia_config.json'

# ---------------------------------------------------------------------------
# Password encryption (DPAPI – tied to current Windows user)
# ---------------------------------------------------------------------------

function ConvertTo-RdcManPassword {
    param([string]$PlainText)
    $bytes     = [System.Text.Encoding]::Unicode.GetBytes($PlainText)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
                     $bytes, $null,
                     [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Convert]::ToBase64String($encrypted)
}

# ---------------------------------------------------------------------------
# GUI file dialogs
# ---------------------------------------------------------------------------

function Get-RdgFileGui {
    param([string]$Title, [string]$InitDir)
    $dlg                  = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title            = $Title
    $dlg.Filter           = 'RDC Manager Files (*.rdg)|*.rdg|All Files (*.*)|*.*'
    $dlg.InitialDirectory = $InitDir
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
    return $null
}

function Save-RdgFileGui {
    param([string]$Title, [string]$InitDir, [string]$DefaultName)
    $dlg                  = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title            = $Title
    $dlg.Filter           = 'RDC Manager Files (*.rdg)|*.rdg|All Files (*.*)|*.*'
    $dlg.InitialDirectory = $InitDir
    $dlg.FileName         = $DefaultName
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileName }
    return $null
}

# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

function Get-Config {
    $myDocs = [Environment]::GetFolderPath('MyDocuments')
    $defaults = [ordered]@{
        TenantFriendlyName = ''
        IspssUsername      = ''
        EnableMfaCache     = $false
        TargetGroupName    = 'CyberArk SIA Connections'
        SourceRdgPath      = $myDocs
        TargetRdgPath      = (Join-Path $myDocs 'SIA_Connections.rdg')
    }

    if (Test-Path $ConfigFile) {
        $saved = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($key in $defaults.Keys) {
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
    Write-Host '=== CyberArk SIA Connection Builder ===' -ForegroundColor Cyan
    Write-Host 'Press Enter to keep the value shown in [brackets].' -ForegroundColor DarkGray
    Write-Host ''

    $Config.TenantFriendlyName = Read-Value 'CyberArk tenant friendly name'   $Config.TenantFriendlyName
    $Config.IspssUsername      = Read-Value 'ISPSS username'                   $Config.IspssUsername
    $Config.TargetGroupName    = Read-Value 'Target group name in output file' $Config.TargetGroupName

    $mfaHint = if ($Config.EnableMfaCache) { 'Y' } else { 'N' }
    $mfaVal  = Read-Host "Enable MFA caching token (/m flag)? (Y/N) [$mfaHint]"
    if ($mfaVal) { $Config.EnableMfaCache = ($mfaVal -match '^[Yy]') }

    # Source RDG file
    Write-Host ''
    $srcHint = if ($Config.SourceRdgPath) { " [$($Config.SourceRdgPath)]" } else { '' }
    Write-Host "Source RDG file${srcHint}" -ForegroundColor White
    $srcVal = Read-Host '  Type path, or press Enter to browse'
    if ($srcVal) {
        $Config.SourceRdgPath = $srcVal.Trim('"')
    } else {
        $initDir = if ($Config.SourceRdgPath -and (Test-Path (Split-Path $Config.SourceRdgPath -Parent))) {
            Split-Path $Config.SourceRdgPath -Parent
        } else {
            [Environment]::GetFolderPath('MyDocuments')
        }
        $path = Get-RdgFileGui 'Select source RDG file' $initDir
        if ($path) { $Config.SourceRdgPath = $path }
    }

    # Target RDG file
    Write-Host ''
    $tgtHint = if ($Config.TargetRdgPath) { " [$($Config.TargetRdgPath)]" } else { '' }
    Write-Host "Target RDG output file${tgtHint}" -ForegroundColor White
    $tgtVal = Read-Host '  Type path, or press Enter to browse'
    if ($tgtVal) {
        $tgtVal = $tgtVal.Trim('"')
        if (-not $tgtVal.EndsWith('.rdg')) { $tgtVal += '.rdg' }
        $Config.TargetRdgPath = $tgtVal
    } else {
        $initDir = if ($Config.TargetRdgPath -and (Test-Path (Split-Path $Config.TargetRdgPath -Parent))) {
            Split-Path $Config.TargetRdgPath -Parent
        } else {
            [Environment]::GetFolderPath('MyDocuments')
        }
        $defName = if ($Config.TargetRdgPath) { Split-Path $Config.TargetRdgPath -Leaf } else { 'SIA_Connections.rdg' }
        $path = Save-RdgFileGui 'Save SIA connections file as' $initDir $defName
        if ($path) { $Config.TargetRdgPath = $path }
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
    if (-not $Config.IspssUsername)      { $errs += 'ISPSS username is required.' }
    if (-not $Config.TargetGroupName)    { $errs += 'Target group name is required.' }
    if (-not $Config.SourceRdgPath)      { $errs += 'Source RDG file path is required.' }
    elseif (-not (Test-Path $Config.SourceRdgPath)) {
        $errs += "Source RDG file not found: $($Config.SourceRdgPath)"
    }
    if (-not $Config.TargetRdgPath)      { $errs += 'Target RDG file path is required.' }
    return $errs
}

# ---------------------------------------------------------------------------
# XML: build a single SIA server element from a source <server> element
# ---------------------------------------------------------------------------

function New-SiaServer {
    param(
        [System.Xml.XmlElement]  $Source,
        [System.Xml.XmlDocument] $Doc,
        [string] $Tenant,
        [string] $IspssUser,
        [bool]   $MfaCache
    )

    $origHostname = $Source.properties.name
    $origDisplay  = if ($Source.properties.displayName) { $Source.properties.displayName } else { $origHostname }
    $siaHostname  = "$Tenant.rdp.cyberark.cloud"

    $srv = $Doc.CreateElement('server')

    # -- <properties> -------------------------------------------------------
    $props = $Doc.CreateElement('properties')

    $el = $Doc.CreateElement('name');        $el.InnerText = $siaHostname;              $props.AppendChild($el) | Out-Null
    $el = $Doc.CreateElement('displayName'); $el.InnerText = "$origDisplay (SIA)";      $props.AppendChild($el) | Out-Null

    # Carry over any other properties from the source (comment, etc.)
    foreach ($child in $Source.properties.ChildNodes) {
        if ($child.Name -notin @('name', 'displayName')) {
            $props.AppendChild($Doc.ImportNode($child, $true)) | Out-Null
        }
    }
    $srv.AppendChild($props) | Out-Null

    # -- <logonCredentials> -------------------------------------------------
    $username = "secureaccess /i $IspssUser /s $Tenant /a $origHostname"
    if ($MfaCache) { $username += ' /m' }

    $creds = $Doc.CreateElement('logonCredentials')
    $creds.SetAttribute('inherit', 'None')

    $el = $Doc.CreateElement('profileName'); $el.SetAttribute('scope', 'Local'); $el.InnerText = "SIA_$origHostname"
    $creds.AppendChild($el) | Out-Null
    $el = $Doc.CreateElement('userName');  $el.InnerText = $username
    $creds.AppendChild($el) | Out-Null
    $el = $Doc.CreateElement('password');  $el.InnerText = ''
    $creds.AppendChild($el) | Out-Null
    $el = $Doc.CreateElement('domain');    $el.InnerText = ''
    $creds.AppendChild($el) | Out-Null

    $srv.AppendChild($creds) | Out-Null

    # -- <gatewaySettings> — inherited from file-level definition -------------
    $gw = $Doc.CreateElement('gatewaySettings')
    $gw.SetAttribute('inherit', 'FromParent')
    $srv.AppendChild($gw) | Out-Null

    # -- Remaining settings inherited from parent ---------------------------
    foreach ($setting in @('connectionSettings', 'remoteDesktop', 'localResources', 'securitySettings', 'displaySettings')) {
        $el = $Doc.CreateElement($setting)
        $el.SetAttribute('inherit', 'FromParent')
        $srv.AppendChild($el) | Out-Null
    }

    return $srv
}

# ---------------------------------------------------------------------------
# Returns $true if a server element already targets the SIA gateway
# ---------------------------------------------------------------------------

function Test-IsSiaServer {
    param([System.Xml.XmlElement]$Server, [string]$Tenant)
    return $Server.properties.name -eq "$Tenant.rdp.cyberark.cloud"
}

# ---------------------------------------------------------------------------
# XML: recursively mirror a group, converting all servers to SIA format
# ---------------------------------------------------------------------------

function Copy-GroupToSia {
    param(
        [System.Xml.XmlElement]  $SrcGroup,
        [System.Xml.XmlElement]  $DstGroup,
        [System.Xml.XmlDocument] $Doc,
        [string] $Tenant,
        [string] $IspssUser,
        [bool]   $MfaCache
    )

    # Copy group <properties> verbatim
    if ($SrcGroup.properties) {
        $DstGroup.AppendChild($Doc.ImportNode($SrcGroup.properties, $true)) | Out-Null
    }

    # Recurse into child groups
    foreach ($childGroup in @($SrcGroup.SelectNodes('group'))) {
        $newGroup = $Doc.CreateElement('group')
        Copy-GroupToSia $childGroup $newGroup $Doc $Tenant $IspssUser $MfaCache
        $DstGroup.AppendChild($newGroup) | Out-Null
    }

    # Convert servers in this group (pass through unchanged if already SIA)
    foreach ($server in @($SrcGroup.SelectNodes('server'))) {
        if (Test-IsSiaServer $server $Tenant) {
            $DstGroup.AppendChild($Doc.ImportNode($server, $true)) | Out-Null
        } else {
            $DstGroup.AppendChild(
                (New-SiaServer -Source $server -Doc $Doc -Tenant $Tenant -IspssUser $IspssUser -MfaCache $MfaCache)
            ) | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# Main transform: source .rdg -> new SIA .rdg
# ---------------------------------------------------------------------------

function New-SiaRdgFile {
    param(
        [string] $SourcePath,
        [string] $TargetPath,
        [string] $GroupName,
        [string] $Tenant,
        [string] $IspssUser,
        [bool]   $MfaCache
    )

    $srcXml  = [xml](Get-Content $SourcePath -Raw -Encoding UTF8)
    $srcFile = $srcXml.RDCMan.file
    if (-not $srcFile) { throw "Not a valid RDCMan file: $SourcePath" }

    $progVer   = if ($srcXml.RDCMan.programVersion) { $srcXml.RDCMan.programVersion } else { '2.90' }
    $schemaVer = if ($srcXml.RDCMan.schemaVersion)  { $srcXml.RDCMan.schemaVersion }  else { '3' }

    $doc  = New-Object System.Xml.XmlDocument
    $decl = $doc.CreateXmlDeclaration('1.0', 'utf-8', $null)
    $doc.AppendChild($decl) | Out-Null

    $root = $doc.CreateElement('RDCMan')
    $root.SetAttribute('programVersion', $progVer)
    $root.SetAttribute('schemaVersion',  $schemaVer)
    $doc.AppendChild($root) | Out-Null

    $fileEl = $doc.CreateElement('file')
    $root.AppendChild($fileEl) | Out-Null

    # Named gateway credential profile — SIA_GW_<tenant>
    $credProfiles = $doc.CreateElement('credentialsProfiles')
    $cp = $doc.CreateElement('credentialsProfile')
    $el = $doc.CreateElement('profileName'); $el.SetAttribute('scope', 'File'); $el.InnerText = "SIA_GW_$Tenant"; $cp.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('userName');    $el.InnerText = 'secureaccess@cyberark';                              $cp.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('password');    $el.InnerText = ConvertTo-RdcManPassword 'secureaccess';              $cp.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('domain');      $el.InnerText = '';                                                   $cp.AppendChild($el) | Out-Null
    $credProfiles.AppendChild($cp) | Out-Null
    $fileEl.AppendChild($credProfiles) | Out-Null

    # File-level properties (the name shown in the RDCMan tree)
    $fileProps = $doc.CreateElement('properties')
    $el = $doc.CreateElement('name');     $el.InnerText = $GroupName; $fileProps.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('expanded'); $el.InnerText = 'True';     $fileProps.AppendChild($el) | Out-Null
    $fileEl.AppendChild($fileProps) | Out-Null

    # File-level gateway settings — all groups and servers inherit this
    $fileGw = $doc.CreateElement('gatewaySettings')
    $fileGw.SetAttribute('inherit', 'None')
    $el = $doc.CreateElement('hostname');    $el.InnerText = "$Tenant.rdp.cyberark.cloud";        $fileGw.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('logonMethod'); $el.InnerText = '0';                                 $fileGw.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('username');    $el.InnerText = 'secureaccess@cyberark';             $fileGw.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('password');    $el.InnerText = ConvertTo-RdcManPassword 'secureaccess'; $fileGw.AppendChild($el) | Out-Null
    $el = $doc.CreateElement('domain');      $el.InnerText = '';                                  $fileGw.AppendChild($el) | Out-Null
    $fileEl.AppendChild($fileGw) | Out-Null

    # Mirror all top-level groups from source
    foreach ($srcGroup in @($srcFile.SelectNodes('group'))) {
        $newGroup = $doc.CreateElement('group')
        Copy-GroupToSia $srcGroup $newGroup $doc $Tenant $IspssUser $MfaCache
        $fileEl.AppendChild($newGroup) | Out-Null
    }

    # Mirror any servers sitting directly under <file> (not inside a group)
    foreach ($srcServer in @($srcFile.SelectNodes('server'))) {
        if (Test-IsSiaServer $srcServer $Tenant) {
            $fileEl.AppendChild($doc.ImportNode($srcServer, $true)) | Out-Null
        } else {
            $fileEl.AppendChild(
                (New-SiaServer -Source $srcServer -Doc $doc -Tenant $Tenant -IspssUser $IspssUser -MfaCache $MfaCache)
            ) | Out-Null
        }
    }

    # Write with consistent indentation
    $xmlSettings               = New-Object System.Xml.XmlWriterSettings
    $xmlSettings.Indent        = $true
    $xmlSettings.IndentChars   = '  '
    $xmlSettings.Encoding      = [System.Text.Encoding]::UTF8

    $writer = [System.Xml.XmlWriter]::Create($TargetPath, $xmlSettings)
    try { $doc.Save($writer) } finally { $writer.Close() }
}

# ---------------------------------------------------------------------------
# Count servers in a source file (for the summary line)
# ---------------------------------------------------------------------------

function Get-ServerCount {
    param([string]$Path)
    try {
        $xml = [xml](Get-Content $Path -Raw -Encoding UTF8)
        return @($xml.SelectNodes('//server')).Count
    } catch { return 0 }
}

# ===========================================================================
# ENTRY POINT — only runs when the script is invoked directly, not dot-sourced
# ===========================================================================

function Invoke-SIABuilder {
    $config = Get-Config
    $config = Invoke-ConfigPrompt $config

    # Validate before saving so a bad path doesn't persist
    $errors = Test-Config $config
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-Host 'Cannot proceed — missing or invalid settings:' -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  • $_" -ForegroundColor Red }
        exit 1
    }

    Save-Config $config

    # Summary
    $serverCount = Get-ServerCount $config.SourceRdgPath
    Write-Host ''
    Write-Host '--- Summary ---' -ForegroundColor Cyan
    Write-Host "  Source file     : $($config.SourceRdgPath) ($serverCount server(s) found)"
    Write-Host "  Output file     : $($config.TargetRdgPath)"
    Write-Host "  Output group    : $($config.TargetGroupName)"
    Write-Host "  Tenant          : $($config.TenantFriendlyName)  →  $($config.TenantFriendlyName).rdp.cyberark.cloud"
    Write-Host "  ISPSS user      : $($config.IspssUsername)"
    Write-Host "  MFA cache (/m)  : $($config.EnableMfaCache)"
    Write-Host ''

    $confirm = Read-Host 'Proceed? (Y/N) [Y]'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host 'Building SIA connections file...' -ForegroundColor Cyan

    try {
        New-SiaRdgFile `
            -SourcePath  $config.SourceRdgPath `
            -TargetPath  $config.TargetRdgPath `
            -GroupName   $config.TargetGroupName `
            -Tenant      $config.TenantFriendlyName `
            -IspssUser   $config.IspssUsername `
            -MfaCache    $config.EnableMfaCache

        Write-Host "Done. Output written to: $($config.TargetRdgPath)" -ForegroundColor Green
        Write-Host 'Note: Gateway passwords are encrypted with your Windows user account' -ForegroundColor DarkGray
        Write-Host '      and will only work when opened as the same Windows user.' -ForegroundColor DarkGray
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIABuilder
}
