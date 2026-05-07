#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticates to CyberArk SIA and refreshes MFA-caching RDP passwords in a Royal TS (.rtsz) document.
.DESCRIPTION
    Reads tenant/user settings from sia_config.json, authenticates via CyberArk Identity,
    retrieves an RDP MFA caching token from the SIA API, then updates the CredentialPassword
    of every RDP connection whose username contains the /m flag.
    Royal TS handles password encryption internally — no DPAPI call is required.
#>

[CmdletBinding()]
param(
    [switch]$DebugMode
)

Add-Type -AssemblyName System.Windows.Forms

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ConfigFile       = Join-Path $PSScriptRoot 'sia_config.json'
$Script:DebugMode = $DebugMode.IsPresent

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
# GUI file dialog
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

# ---------------------------------------------------------------------------
# Config loading (shared schema with SIAnable scripts)
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

# ---------------------------------------------------------------------------
# Debug trace helper
# ---------------------------------------------------------------------------

function Trace-ApiCall {
    param(
        [string]$Uri,
        [string]$Body,
        $Response,
        [switch]$RedactAnswer
    )
    if (-not $Script:DebugMode) { return }

    if ($Body) {
        $displayBody = if ($RedactAnswer) {
            $Body -replace '("Answer"\s*:\s*")[^"]*"', '$1****"'
        } else { $Body }
        Write-Host "  [DBG] -> POST $Uri" -ForegroundColor DarkCyan
        Write-Host "         Req : $displayBody" -ForegroundColor DarkCyan
    }
    if ($null -ne $Response) {
        $respJson = $Response | ConvertTo-Json -Depth 6 -Compress
        $respJson = $respJson -replace '"([A-Za-z0-9+/=_.\-]{40,})"', '"[...token...]"'
        Write-Host "         Resp: $respJson" -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# CyberArk Identity authentication — returns the platform token
# ---------------------------------------------------------------------------

function Invoke-CyberArkIdentityAuth {
    param([string]$IdentityTenantId, [string]$Username)

    $idpBase     = "https://$IdentityTenantId.id.cyberark.cloud"
    $jsonHeaders = @{
        'Content-Type'         = 'application/json'
        'X-IDAP-NATIVE-CLIENT' = 'true'
        'OobIdPAuth'           = 'true'
    }

    Write-Host "Connecting to $idpBase ..." -ForegroundColor Cyan

    $startBody = @{
        User                  = $Username
        Version               = '1.0'
        PlatformTokenResponse = $true
        AssociatedEntityType  = 'API'
        MfaRequestor          = 'DeviceAgent'
    } | ConvertTo-Json

    $webSession = $null
    try {
        $startResp = Invoke-RestMethod -Uri "$idpBase/Security/StartAuthentication" `
                         -Method Post -Headers $jsonHeaders -Body $startBody `
                         -SessionVariable webSession -ErrorAction Stop
        Trace-ApiCall -Uri "$idpBase/Security/StartAuthentication" -Body $startBody -Response $startResp
    } catch {
        throw "StartAuthentication request failed: $_"
    }

    if ($startResp.success -ne $true) {
        throw "StartAuthentication failed: $($startResp.Message)"
    }

    $sessionId     = $startResp.Result.SessionId
    $platformToken = $null

    foreach ($challenge in $startResp.Result.Challenges) {
        $mechanisms = @($challenge.Mechanisms)

        $mechanism = if ($mechanisms.Count -eq 1) {
            $mechanisms[0]
        } else {
            Write-Host ''
            Write-Host 'Available authentication methods:' -ForegroundColor White
            for ($i = 0; $i -lt $mechanisms.Count; $i++) {
                Write-Host "  [$($i + 1)] $($mechanisms[$i].PromptSelectMech)"
            }
            do {
                $pick = Read-Host "Select method (1-$($mechanisms.Count))"
            } while ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $mechanisms.Count)
            $mechanisms[[int]$pick - 1]
        }

        $mechId       = $mechanism.MechanismId
        $prompt       = if ($mechanism.PromptMechChosen) { $mechanism.PromptMechChosen } else { $mechanism.PromptSelectMech }
        $needsOobStart = $mechanism.AnswerType -in @('StartOob', 'StartTextOob')
        $needsText     = $mechanism.AnswerType -in @('Text', 'StartTextOob')

        if (-not $needsOobStart) {
            $answer = if ($mechanism.Name -eq 'UP') {
                $ss = Read-Host $prompt -AsSecureString
                [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
            } else {
                Read-Host $prompt
            }
            $body = @{
                SessionId   = $sessionId
                MechanismId = $mechId
                Action      = 'Answer'
                Answer      = $answer
            } | ConvertTo-Json
            try {
                $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                               -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                Trace-ApiCall -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp -RedactAnswer:($mechanism.Name -eq 'UP')
            } catch {
                throw "AdvanceAuthentication failed: $_"
            }
            if ($advResp.success -eq $false) { throw "CyberArk rejected the response: $($advResp.Message)" }
        } else {
            $body = @{
                SessionId   = $sessionId
                MechanismId = $mechId
                Action      = 'StartOOB'
                Answer      = ''
            } | ConvertTo-Json
            try {
                $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                               -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                Trace-ApiCall -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp
            } catch {
                throw "AdvanceAuthentication (StartOOB) failed: $_"
            }
            if ($advResp.success -eq $false) { throw "CyberArk rejected StartOOB: $($advResp.Message)" }

            if ($advResp.Result.Summary -eq 'OobPending') {
                if (-not $needsText) {
                    Write-Host "$prompt — approve on your device..." -ForegroundColor Yellow
                } else {
                    Write-Host '  Waiting for challenge to initialise...' -ForegroundColor DarkGray
                }
                $deadline = (Get-Date).AddSeconds(360)
                while ($advResp.Result.Summary -eq 'OobPending' -and (Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 500
                    $body = @{
                        SessionId   = $sessionId
                        MechanismId = $mechId
                        Action      = 'Poll'
                        Answer      = ''
                    } | ConvertTo-Json
                    try {
                        $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                                       -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                        Trace-ApiCall -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp
                    } catch {
                        throw "OOB poll failed: $_"
                    }
                    if ($advResp.success -eq $false) { throw "CyberArk rejected the OOB attempt: $($advResp.Message)" }
                    if (-not $needsText -and $advResp.Result.Summary -eq 'OobPending') {
                        Write-Host '  Still waiting...' -ForegroundColor DarkGray
                    }
                }
            }

            if ($needsText -and $advResp.Result.Summary -ne 'LoginSuccess') {
                $answer = Read-Host $prompt
                $body = @{
                    SessionId   = $sessionId
                    MechanismId = $mechId
                    Action      = 'Answer'
                    Answer      = $answer
                } | ConvertTo-Json
                try {
                    $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                                   -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                    Trace-ApiCall -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp
                } catch {
                    throw "AdvanceAuthentication (Answer) failed: $_"
                }
                if ($advResp.success -eq $false) { throw "CyberArk rejected the response: $($advResp.Message)" }
            }
        }

        switch ($advResp.Result.Summary) {
            'LoginSuccess' {
                $platformToken = if ($advResp.Result.Token) {
                    $advResp.Result.Token
                } elseif ($advResp.Result.Auth) {
                    $advResp.Result.Auth
                } else {
                    $advResp.Result.PlatformToken
                }
            }
            'LoginFailure' {
                throw "Authentication failed: $($advResp.Result.Message)"
            }
            { $_ -in 'NewPackage', 'StartNextChallenge', 'Continue' } {
                # More challenges remain; continue to next iteration
            }
            default {
                throw "Unexpected authentication response: $($advResp.Result.Summary)"
            }
        }

        if ($platformToken) { break }
    }

    if (-not $platformToken) { throw 'Authentication completed but no token was returned.' }
    return $platformToken
}

# ---------------------------------------------------------------------------
# Retrieve the SIA RDP MFA caching token
# ---------------------------------------------------------------------------

function Get-SiaMfaCacheToken {
    param([string]$Tenant, [string]$BearerToken)

    $uri     = "https://$Tenant-userportal.cyberark.cloud/api/adb/sso/acquire"
    $headers = @{
        'Authorization' = "Bearer $BearerToken"
        'Content-Type'  = 'application/json'
    }
    $body = @{ tokenType = 'password'; service = 'DPA-RDP' } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ErrorAction Stop
        Trace-ApiCall -Uri $uri -Body $body -Response $resp
    } catch {
        throw "SIA token request failed: $_"
    }

    $token = $resp.token.key
    if (-not $token) {
        throw "SIA response did not contain a token.key value.`nRaw: $($resp | ConvertTo-Json -Depth 5)"
    }
    return $token
}

# ---------------------------------------------------------------------------
# Update every /m RDP connection in the document with the token
# Returns the count of connections updated
# ---------------------------------------------------------------------------

function ConvertTo-PlainText {
    param([SecureString]$SecureString)
    if (-not $SecureString -or $SecureString.Length -eq 0) { return $null }
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
}

function Update-RtszMfaPasswords {
    param([string]$RtszPath, [string]$MfaToken, [SecureString]$DocumentPassword)

    $plain  = ConvertTo-PlainText $DocumentPassword
    $store  = New-RoyalStore -UserName "$env:USERDOMAIN\$env:USERNAME"
    $doc    = if ($plain) {
        Open-RoyalDocument -FileName $RtszPath -Store $store -Password $plain
    } else {
        Open-RoyalDocument -FileName $RtszPath -Store $store
    }
    $updated = 0

    try {
        foreach ($conn in @(Get-RoyalObject -Document $doc -Type RoyalRDSConnection)) {
            # EffectiveUsername resolves the final username regardless of credential mode
            if ($conn.EffectiveUsername -notmatch '/m\b') { continue }
            Set-RoyalObjectValue -Object $conn -Property 'CredentialPassword' -Value $MfaToken
            $updated++
        }

        if ($updated -gt 0) {
            Out-RoyalDocument -Document $doc
        }
    } finally {
        Close-RoyalDocument -Document $doc | Out-Null
    }

    return $updated
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

function Invoke-SIAuthRoyalTS {
    Invoke-ModuleSetup

    $config = Get-Config

    if (-not $config.TenantFriendlyName -or -not $config.IdentityTenantId -or -not $config.IspssUsername) {
        Write-Host 'No saved tenant/user config found. Run SIAnable-for-RoyalTS.ps1 first to set it up.' -ForegroundColor Red
        exit 1
    }

    Write-Host ''
    Write-Host '=== CyberArk SIA MFA Token Refresh (Royal TS) ===' -ForegroundColor Cyan
    Write-Host "  Tenant          : $($config.TenantFriendlyName)"
    Write-Host "  Identity tenant : $($config.IdentityTenantId)"
    Write-Host "  User            : $($config.IspssUsername)"
    Write-Host ''

    # --- Select .rtsz file ---
    $initDir = if ($config.TargetRtszPath -and (Test-Path (Split-Path $config.TargetRtszPath -Parent))) {
        Split-Path $config.TargetRtszPath -Parent
    } else { [Environment]::GetFolderPath('MyDocuments') }

    $rtszHint = if ($config.TargetRtszPath) { " [$($config.TargetRtszPath)]" } else { '' }
    Write-Host "Royal TS document to update${rtszHint}" -ForegroundColor White
    $rtszVal = Read-Host '  Type a path, B to browse, or Enter to keep'

    $rtszPath = if (-not $rtszVal -and $config.TargetRtszPath) {
        $config.TargetRtszPath
    } elseif (-not $rtszVal -or $rtszVal -match '^[Bb]$') {
        Get-RtszFileGui 'Select Royal TS document to update' $initDir
    } else {
        $rtszVal.Trim('"')
    }

    if (-not $rtszPath) { Write-Host 'No file selected. Cancelled.' -ForegroundColor Yellow; exit 0 }
    if (-not (Test-Path $rtszPath)) { Write-Host "File not found: $rtszPath" -ForegroundColor Red; exit 1 }

    # --- Document password (never saved to config) ---
    Write-Host ''
    Write-Host 'Document password (press Enter if not encrypted):' -ForegroundColor White
    $docPassword = Read-Host '  Password' -AsSecureString

    # --- Authenticate ---
    try {
        $bearerToken = Invoke-CyberArkIdentityAuth -IdentityTenantId $config.IdentityTenantId `
                                                   -Username $config.IspssUsername
    } catch {
        Write-Host "Authentication error: $_" -ForegroundColor Red; exit 1
    }
    Write-Host 'Authentication successful.' -ForegroundColor Green

    # --- Retrieve SIA MFA token ---
    try {
        $mfaToken = Get-SiaMfaCacheToken -Tenant $config.TenantFriendlyName -BearerToken $bearerToken
    } catch {
        Write-Host "Token retrieval error: $_" -ForegroundColor Red; exit 1
    }
    Write-Host 'MFA cache token retrieved.' -ForegroundColor Green

    # --- Update document ---
    try {
        $count = Update-RtszMfaPasswords -RtszPath $rtszPath -MfaToken $mfaToken -DocumentPassword $docPassword
    } catch {
        Write-Host "Error updating document: $_" -ForegroundColor Red; exit 1
    }

    if ($count -eq 0) {
        Write-Host 'No /m connections found in the selected document — nothing was updated.' -ForegroundColor Yellow
    } else {
        Write-Host "Updated $count connection(s) in: $rtszPath" -ForegroundColor Green
        Write-Host 'Reload the document in Royal TS to pick up the new token.' -ForegroundColor DarkGray
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIAuthRoyalTS
}
