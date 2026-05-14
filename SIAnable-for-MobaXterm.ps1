#Requires -Version 5.1
<#
.SYNOPSIS
    Converts existing MobaXterm SSH sessions into CyberArk SIA-enabled duplicates,
    prefixed with _SIA, within a dedicated SIA bookmark folder.
.DESCRIPTION
    Reads MobaXterm.ini from the user's AppData folder, finds all SSH sessions
    (protocol type #109#), and writes SIA-prefixed copies into a new bookmark
    group with the hostname and username rewritten for the CyberArk SIA SSH gateway.
    The original file is backed up as MobaXterm.ini.bak before any changes are made.
#>

[CmdletBinding()]
param()

$ConfigFile  = Join-Path $PSScriptRoot 'sia_config.json'
$MobaIniPath = Join-Path $env:APPDATA 'MobaXterm\MobaXterm.ini'

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
        SshKeyFormat       = 'ppk'
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

function Read-Value {
    param([string]$Prompt, [string]$Current)
    $hint = if ($Current) { " [$Current]" } else { '' }
    $val  = Read-Host "${Prompt}${hint}"
    if ($val) { return $val } else { return $Current }
}

# ---------------------------------------------------------------------------
# Interactive config prompt — no file paths needed, MobaXterm.ini is fixed
# ---------------------------------------------------------------------------

function Invoke-ConfigPrompt {
    param($Config)

    Write-Host ''
    Write-Host '=== CyberArk SIA Connection Builder (MobaXterm) ===' -ForegroundColor Cyan
    Write-Host 'Press Enter to keep the value shown in [brackets].' -ForegroundColor DarkGray
    Write-Host ''

    $Config.TenantFriendlyName = Read-Value 'CyberArk tenant friendly name' $Config.TenantFriendlyName
    $Config.IspssUsername      = Read-Value 'ISPSS username'                 $Config.IspssUsername

    $mfaHint = if ($Config.EnableMfaCache) { 'Y' } else { 'N' }
    $mfaVal  = Read-Host "Enable MFA caching (retrieve SSH key via SIAuth-for-SSH)? (Y/N) [$mfaHint]"
    if ($mfaVal) { $Config.EnableMfaCache = ($mfaVal -match '^[Yy]') }

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
    return $errs
}

# ---------------------------------------------------------------------------
# MobaXterm.ini parsing
# Each section is { Name: string, Lines: List[string] }
# ---------------------------------------------------------------------------

function Read-MobaIni {
    param([string]$Path)

    $sections = [System.Collections.Generic.List[pscustomobject]]::new()
    $current  = $null

    foreach ($line in (Get-Content $Path -Encoding UTF8)) {
        if ($line -match '^\[(.+)\]') {
            $current = [pscustomobject]@{
                Name  = $matches[1]
                Lines = [System.Collections.Generic.List[string]]::new()
            }
            $sections.Add($current)
        } elseif ($null -ne $current) {
            $current.Lines.Add($line)
        }
    }

    return $sections
}

function Write-MobaIni {
    param($Sections, [string]$Path)

    $sb = [System.Text.StringBuilder]::new()
    foreach ($s in $Sections) {
        [void]$sb.AppendLine("[$($s.Name)]")
        foreach ($l in $s.Lines) { [void]$sb.AppendLine($l) }
        [void]$sb.AppendLine('')
    }

    # Trim trailing blank lines then write with a single trailing newline
    Set-Content $Path -Value $sb.ToString().TrimEnd() -Encoding UTF8 -NoNewline
}

# ---------------------------------------------------------------------------
# Session discovery — collect all SSH (#109#) sessions across bookmark sections,
# skipping entries already prefixed with SIA_. Each session records its source
# folder name (SubRep) so output can be grouped into matching SIA_ folders.
# ---------------------------------------------------------------------------

function Get-MobaSshSessions {
    param($Sections)

    $sessions = @()
    foreach ($s in ($Sections | Where-Object { $_.Name -like 'Bookmarks*' })) {
        $subRepLine = $s.Lines | Where-Object { $_ -match '^SubRep=' } | Select-Object -First 1
        $subRep     = if ($subRepLine) { $subRepLine -replace '^SubRep=', '' } else { '' }

        foreach ($line in $s.Lines) {
            # Session lines: <name>=<data containing #109#>
            if ($line -notmatch '^([^=]+)=(.*#109#.*)$') { continue }
            $name = $matches[1]
            $data = $matches[2]

            if ($name -match '^SIA_') { continue }   # skip already-converted

            # Field layout (%-delimited after the #109#X prefix):
            # [0] = #109#<subtype>   [1] = hostname   [2] = port   [3] = username ...
            $parts    = $data -split '%'
            $origHost = $parts[1]
            if (-not $origHost) { continue }

            $sessions += [pscustomobject]@{
                Name     = $name
                Data     = $data
                OrigHost = $origHost
                SubRep   = $subRep
            }
        }
    }

    return $sessions
}

# ---------------------------------------------------------------------------
# Build a SIA session string for the given source session.
#
# Always constructs from a known-good full-format template derived from a
# working MobaXterm SIA session, rather than modifying source fields in-place.
# In-place editing is unreliable: source sessions (especially those imported
# from PuTTY) carry non-standard field values that cause MobaXterm to mis-parse
# the username even when the username field itself looks correct.
#
# Only the original port is carried over; all other fields use MobaXterm
# defaults. '#' is encoded as __DIEZE__ per MobaXterm's INI convention.
# _ProfileDir_ is MobaXterm's placeholder for the Windows user profile root.
# ---------------------------------------------------------------------------

function Convert-ToSiaSessionData {
    param(
        [string]$Data,
        [string]$Tenant,
        [string]$IspssUser,
        [string]$OrigHost,
        [bool]$SetKeyFile
    )

    $port     = ($Data -split '%')[2]
    $gw       = "$Tenant.ssh.cyberark.cloud"
    $user     = "${IspssUser}__DIEZE__${Tenant}@${OrigHost}"
    $keyField = if ($SetKeyFile) { "_ProfileDir_\.ssh\cyberark_sia_$Tenant.key" } else { '' }

    return " #109#0%$gw%$port%$user%%-1%-1%%%%%0%0%0%$keyField%%-1%0%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0#$OrigHost%10%-1%0%-1%15%236,236,236%30,30,30%180,180,192%-1%0%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0#0 #-1"
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

function Invoke-SIAnableMobaXterm {
    if (-not (Test-Path $MobaIniPath)) {
        Write-Host "MobaXterm configuration not found: $MobaIniPath" -ForegroundColor Red
        exit 1
    }

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

    $sections    = Read-MobaIni $MobaIniPath
    $sshSessions = Get-MobaSshSessions $sections

    if ($sshSessions.Count -eq 0) {
        Write-Host ''
        Write-Host 'No eligible SSH sessions found in MobaXterm.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host '--- Summary ---' -ForegroundColor Cyan
    Write-Host "  Source         : $MobaIniPath"
    Write-Host "  Tenant         : $($config.TenantFriendlyName)  →  $($config.TenantFriendlyName).ssh.cyberark.cloud"
    Write-Host "  ISPSS user     : $($config.IspssUsername)"
    Write-Host "  MFA cache      : $($config.EnableMfaCache)"
    Write-Host ''
    $groups = $sshSessions | Group-Object SubRep
    Write-Host "  $($sshSessions.Count) SSH session(s) to convert:" -ForegroundColor White
    foreach ($group in $groups) {
        $folderName = if ($group.Name) { "SIA_$($group.Name)" } else { 'SIA_Sessions' }
        Write-Host "  [$folderName]" -ForegroundColor White
        foreach ($s in $group.Group) {
            Write-Host "    $($s.Name)  →  SIA_$($s.Name)"
        }
    }
    Write-Host ''

    $confirm = Read-Host 'Proceed? (Y/N) [Y]'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 0
    }

    # Remove any existing SIA_ bookmark sections so re-runs don't accumulate duplicates
    $sections = [System.Collections.Generic.List[pscustomobject]]@(
        $sections | Where-Object {
            -not ($_.Lines | Where-Object { $_ -match '^SubRep=SIA_' })
        }
    )

    # Find the starting [Bookmarks_N] number for the new sections
    $existingNums = @($sections |
        Where-Object { $_.Name -match '^Bookmarks_(\d+)$' } |
        ForEach-Object { [int]($_.Name -replace 'Bookmarks_', '') })
    $nextNum = if ($existingNums.Count -gt 0) {
        ($existingNums | Measure-Object -Maximum).Maximum + 1
    } else { 1 }

    # Build one SIA_ bookmark section per source folder
    foreach ($group in $groups) {
        $folderName = if ($group.Name) { "SIA_$($group.Name)" } else { 'SIA_Sessions' }
        $siaLines   = [System.Collections.Generic.List[string]]::new()
        $siaLines.Add("SubRep=$folderName")
        $siaLines.Add('ImgNum=42')

        foreach ($session in $group.Group) {
            $siaName = "SIA_$($session.Name)"
            $siaData = Convert-ToSiaSessionData `
                -Data       $session.Data `
                -Tenant     $config.TenantFriendlyName `
                -IspssUser  $config.IspssUsername `
                -OrigHost   $session.OrigHost `
                -SetKeyFile $config.EnableMfaCache
            $siaLines.Add("$siaName=$siaData")
        }

        $sections.Add([pscustomobject]@{
            Name  = "Bookmarks_$nextNum"
            Lines = $siaLines
        })
        $nextNum++
    }

    # Back up original then write
    Copy-Item $MobaIniPath "$MobaIniPath.bak" -Force
    Write-MobaIni -Sections $sections -Path $MobaIniPath

    Write-Host ''
    Write-Host "$($sshSessions.Count) session(s) written to: $MobaIniPath" -ForegroundColor Green
    Write-Host "Original backed up to: $MobaIniPath.bak" -ForegroundColor DarkGray
    if ($config.EnableMfaCache) {
        Write-Host 'Run SIAuth-for-SSH.ps1 to retrieve and store the SSH key.' -ForegroundColor DarkGray
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIAnableMobaXterm
}
