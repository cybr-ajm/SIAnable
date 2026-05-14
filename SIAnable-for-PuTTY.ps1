#Requires -Version 5.1
<#
.SYNOPSIS
    Converts existing PuTTY SSH sessions into CyberArk SIA-enabled duplicates,
    prefixed with _SIA, preserving all original settings with SIA gateway overrides.
#>

[CmdletBinding()]
param()

$ConfigFile    = Join-Path $PSScriptRoot 'sia_config.json'
$PuttySessions = 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions'

# ---------------------------------------------------------------------------
# Shared helper — compute the local SSH key path used by both scripts
# ---------------------------------------------------------------------------

function Get-SshKeyPath {
    param([string]$Tenant, [string]$Format)
    $ext = if ($Format -eq 'ppk') { '.ppk' } else { '' }
    Join-Path $env:USERPROFILE ".ssh\cyberark_sia_$Tenant$ext"
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
# Interactive config prompt
# ---------------------------------------------------------------------------

function Invoke-ConfigPrompt {
    param($Config)

    Write-Host ''
    Write-Host '=== CyberArk SIA Connection Builder (PuTTY) ===' -ForegroundColor Cyan
    Write-Host 'Press Enter to keep the value shown in [brackets].' -ForegroundColor DarkGray
    Write-Host ''

    $Config.TenantFriendlyName = Read-Value 'CyberArk tenant friendly name' $Config.TenantFriendlyName
    $Config.IspssUsername      = Read-Value 'ISPSS username'                 $Config.IspssUsername

    $mfaHint = if ($Config.EnableMfaCache) { 'Y' } else { 'N' }
    $mfaVal  = Read-Host "Enable MFA caching (store SSH key per session)? (Y/N) [$mfaHint]"
    if ($mfaVal) { $Config.EnableMfaCache = ($mfaVal -match '^[Yy]') }

    if ($Config.EnableMfaCache) {
        do {
            $fmtVal = Read-Value 'SSH key format (ppk/openssh)' $Config.SshKeyFormat
        } while ($fmtVal -notin @('ppk', 'openssh'))
        $Config.SshKeyFormat = $fmtVal
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
    if ($Config.EnableMfaCache -and $Config.SshKeyFormat -notin @('ppk', 'openssh')) {
        $errs += 'SSH key format must be ppk or openssh.'
    }
    return $errs
}

# ---------------------------------------------------------------------------
# PuTTY session discovery — SSH only, skip already-converted _SIA sessions
# ---------------------------------------------------------------------------

function Get-PuttySshSessions {
    if (-not (Test-Path $PuttySessions)) { return @() }

    @(Get-ChildItem $PuttySessions | Where-Object {
        if ($_.PSChildName -match '^_SIA') { return $false }
        $proto = (Get-ItemProperty $_.PSPath -Name 'Protocol' -ErrorAction SilentlyContinue).Protocol
        return (-not $proto -or $proto -eq 'ssh')
    })
}

# ---------------------------------------------------------------------------
# Create a single SIA-enabled PuTTY session in the registry
# ---------------------------------------------------------------------------

function New-SiaPuttySession {
    param(
        $SourceKey,
        [string]$Tenant,
        [string]$IspssUser,
        [bool]$MfaCache,
        [string]$KeyFormat
    )

    $srcPath  = $SourceKey.PSPath
    $newName  = "_SIA$($SourceKey.PSChildName)"
    $dstPath  = "$PuttySessions\$newName"

    $origHost = (Get-ItemProperty $srcPath -Name 'HostName' -ErrorAction SilentlyContinue).HostName
    if (-not $origHost) {
        Write-Host "    Skipped — no HostName value." -ForegroundColor DarkGray
        return $false
    }

    # Recreate the destination key cleanly so stale values don't linger
    if (Test-Path $dstPath) { Remove-Item $dstPath -Force -Recurse }
    New-Item $dstPath -Force | Out-Null

    # Copy all values from source, preserving registry value kinds
    $srcRegKey = Get-Item $srcPath
    foreach ($valueName in $srcRegKey.GetValueNames()) {
        $value = $srcRegKey.GetValue($valueName)
        $kind  = $srcRegKey.GetValueKind($valueName)
        Set-ItemProperty $dstPath -Name $valueName -Value $value -Type $kind
    }

    # Override with SIA connection details
    # SSH username format: <IspssUser>#<tenant>@<originalHost>
    # PuTTY appends @<HostName> to produce the full SSH target string
    Set-ItemProperty $dstPath -Name 'HostName' -Value "$Tenant.ssh.cyberark.cloud" -Type String
    Set-ItemProperty $dstPath -Name 'UserName'  -Value "$IspssUser#$Tenant@$origHost"  -Type String

    if ($MfaCache) {
        # Point PuTTY at the key file SIAuth-for-PuTTY will store
        # PuTTY uses 'PublicKeyFile' as the registry value name for the private key path
        $keyPath = Get-SshKeyPath -Tenant $Tenant -Format $KeyFormat
        Set-ItemProperty $dstPath -Name 'PublicKeyFile' -Value $keyPath -Type String
    }

    return $true
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

function Invoke-SIAnablePuTTY {
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

    $sessions = Get-PuttySshSessions
    if ($sessions.Count -eq 0) {
        Write-Host ''
        Write-Host 'No eligible SSH sessions found in PuTTY.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    Write-Host '--- Summary ---' -ForegroundColor Cyan
    Write-Host "  Tenant         : $($config.TenantFriendlyName)  →  $($config.TenantFriendlyName).ssh.cyberark.cloud"
    Write-Host "  ISPSS user     : $($config.IspssUsername)"
    Write-Host "  MFA cache      : $($config.EnableMfaCache)"
    if ($config.EnableMfaCache) {
        Write-Host "  Key format     : $($config.SshKeyFormat)"
        Write-Host "  Key path       : $(Get-SshKeyPath $config.TenantFriendlyName $config.SshKeyFormat)"
    }
    Write-Host ''
    Write-Host "  $($sessions.Count) SSH session(s) to convert:" -ForegroundColor White
    foreach ($s in $sessions) {
        $src = [System.Uri]::UnescapeDataString($s.PSChildName)
        $dst = [System.Uri]::UnescapeDataString("_SIA$($s.PSChildName)")
        Write-Host "    $src  →  $dst"
    }
    Write-Host ''

    $confirm = Read-Host 'Proceed? (Y/N) [Y]'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 0
    }

    Write-Host ''
    $created = 0
    foreach ($session in $sessions) {
        $displayName = [System.Uri]::UnescapeDataString($session.PSChildName)
        Write-Host "  Converting: $displayName" -ForegroundColor Cyan
        $ok = New-SiaPuttySession `
            -SourceKey $session `
            -Tenant    $config.TenantFriendlyName `
            -IspssUser $config.IspssUsername `
            -MfaCache  $config.EnableMfaCache `
            -KeyFormat $config.SshKeyFormat
        if ($ok) { $created++ }
    }

    Write-Host ''
    Write-Host "$created session(s) created in PuTTY." -ForegroundColor Green
    if ($config.EnableMfaCache) {
        Write-Host 'Run SIAuth-for-PuTTY.ps1 to retrieve and store the SSH key.' -ForegroundColor DarkGray
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIAnablePuTTY
}
