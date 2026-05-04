#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticates to CyberArk SIA and refreshes MFA-caching RDP passwords in an .rdg file.
.DESCRIPTION
    Reads tenant/user settings from sia_config.json, authenticates via CyberArk Identity,
    retrieves an RDP MFA caching token from the SIA API, then updates the password field
    of every connection in the selected .rdg file whose username contains the /m flag.
    Passwords are DPAPI-encrypted for RDCMan compatibility.
#>

[CmdletBinding()]
param(
    [switch]$DebugMode
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ConfigFile          = Join-Path $PSScriptRoot 'sia_config.json'
$Script:DebugMode    = $DebugMode.IsPresent

# ---------------------------------------------------------------------------
# DPAPI encryption (identical to SIAnable-for-RDCMan)
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
# GUI file dialog
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

# ---------------------------------------------------------------------------
# Config loading (shared schema with SIAnable-for-RDCMan)
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
# Debug trace helper — emits request/response details when -DebugMode is set
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
        # Truncate long token/base64 strings so output stays readable
        $respJson = $Response | ConvertTo-Json -Depth 6 -Compress
        $respJson = $respJson -replace '"([A-Za-z0-9+/=_.\-]{40,})"', '"[...token...]"'
        Write-Host "         Resp: $respJson" -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# CyberArk Identity authentication
# Returns the platform token (bearer token for SIA API calls)
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
        User                 = $Username
        Version              = '1.0'
        PlatformTokenResponse = $true
        AssociatedEntityType = 'API'
        MfaRequestor         = 'DeviceAgent'
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

        # If multiple mechanisms are available let the user choose
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

        $advResp = $null

        if (-not $needsOobStart) {
            # Text-only (password, RADIUS): prompt and Answer directly
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
            if ($advResp.success -eq $false) {
                throw "CyberArk rejected the response: $($advResp.Message)"
            }
        } else {
            # Step 1: StartOOB — triggers delivery or initialises the challenge
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
            if ($advResp.success -eq $false) {
                throw "CyberArk rejected StartOOB: $($advResp.Message)"
            }

            # Step 2: Poll while OobPending (500 ms interval, up to 360 s per SDK defaults)
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
                    if ($advResp.success -eq $false) {
                        throw "CyberArk rejected the OOB attempt: $($advResp.Message)"
                    }
                    if (-not $needsText -and $advResp.Result.Summary -eq 'OobPending') {
                        Write-Host '  Still waiting...' -ForegroundColor DarkGray
                    }
                }
            }

            # Step 3: If a text answer is needed and auth isn't already complete, collect and submit it
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
                if ($advResp.success -eq $false) {
                    throw "CyberArk rejected the response: $($advResp.Message)"
                }
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

    if (-not $platformToken) {
        throw 'Authentication completed but no token was returned.'
    }

    return $platformToken
}

# ---------------------------------------------------------------------------
# Retrieve the SIA RDP MFA caching token
# ---------------------------------------------------------------------------

function Get-DpaMfaCacheToken {
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
# Update every /m logonCredentials entry in the RDG file with the encrypted token
# Returns the count of entries updated
# ---------------------------------------------------------------------------

function Update-RdgMfaPasswords {
    param([string]$RdgPath, [string]$EncryptedToken)

    $xml     = [xml](Get-Content $RdgPath -Raw -Encoding UTF8)
    $updated = 0

    # Credentials can be inline per-server (logonCredentials) or shared file/group-level profiles
    # (credentialsProfile). Search both.
    foreach ($creds in @($xml.SelectNodes('//logonCredentials | //credentialsProfile'))) {
        $userEl = $creds.SelectSingleNode('userName')
        if (-not $userEl -or $userEl.InnerText -notmatch '/m\b') { continue }

        $pwEl = $creds.SelectSingleNode('password')
        if ($pwEl) {
            $pwEl.InnerText = $EncryptedToken
        } else {
            $newPw           = $xml.CreateElement('password')
            $newPw.InnerText = $EncryptedToken
            $creds.AppendChild($newPw) | Out-Null
        }
        $updated++
    }

    if ($updated -eq 0) { return 0 }

    $xmlSettings             = New-Object System.Xml.XmlWriterSettings
    $xmlSettings.Indent      = $true
    $xmlSettings.IndentChars = '  '
    $xmlSettings.Encoding    = [System.Text.Encoding]::UTF8

    $writer = [System.Xml.XmlWriter]::Create($RdgPath, $xmlSettings)
    try   { $xml.Save($writer) }
    finally { $writer.Close() }

    return $updated
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

function Invoke-SIAuth {
    $config = Get-Config

    Write-Host ''
    Write-Host '=== CyberArk SIA MFA Token Refresh ===' -ForegroundColor Cyan

    # Prompt inline for any required fields not yet in the config, then persist them
    $dirty = $false
    if (-not $config.TenantFriendlyName) {
        $config.TenantFriendlyName = Read-Host 'CyberArk tenant friendly name'
        $dirty = $true
    }
    if (-not $config.IdentityTenantId) {
        $config.IdentityTenantId = Read-Host 'CyberArk Identity tenant ID'
        $dirty = $true
    }
    if (-not $config.IspssUsername) {
        $config.IspssUsername = Read-Host 'ISPSS username'
        $dirty = $true
    }
    if (-not $config.TenantFriendlyName -or -not $config.IdentityTenantId -or -not $config.IspssUsername) {
        Write-Host 'Tenant name, Identity tenant ID, and ISPSS username are all required.' -ForegroundColor Red
        exit 1
    }
    if ($dirty) {
        $config | ConvertTo-Json | Set-Content $ConfigFile -Encoding UTF8
    }

    Write-Host "  Tenant          : $($config.TenantFriendlyName)"
    Write-Host "  Identity tenant : $($config.IdentityTenantId)"
    Write-Host "  User            : $($config.IspssUsername)"
    Write-Host ''

    # --- Select RDG file ---
    $initDir = if ($config.TargetRdgPath -and (Test-Path (Split-Path $config.TargetRdgPath -Parent))) {
        Split-Path $config.TargetRdgPath -Parent
    } else {
        [Environment]::GetFolderPath('MyDocuments')
    }

    $rdgHint = if ($config.TargetRdgPath) { " [$($config.TargetRdgPath)]" } else { '' }
    Write-Host "RDG file to update${rdgHint}" -ForegroundColor White
    $rdgVal = Read-Host '  Type a path, B to browse, or Enter to keep'

    $rdgPath = if (-not $rdgVal -and $config.TargetRdgPath) {
        $config.TargetRdgPath
    } elseif (-not $rdgVal -or $rdgVal -match '^[Bb]$') {
        Get-RdgFileGui 'Select RDG file to update' $initDir
    } else {
        $rdgVal.Trim('"')
    }

    if (-not $rdgPath) {
        Write-Host 'No file selected. Cancelled.' -ForegroundColor Yellow
        exit 0
    }
    if (-not (Test-Path $rdgPath)) {
        Write-Host "File not found: $rdgPath" -ForegroundColor Red
        exit 1
    }

    # --- Authenticate ---
    try {
        $bearerToken = Invoke-CyberArkIdentityAuth -IdentityTenantId $config.IdentityTenantId `
                                                   -Username $config.IspssUsername
    } catch {
        Write-Host "Authentication error: $_" -ForegroundColor Red
        exit 1
    }
    Write-Host 'Authentication successful.' -ForegroundColor Green

    # --- Retrieve SIA MFA token ---
    try {
        $mfaToken = Get-DpaMfaCacheToken -Tenant $config.TenantFriendlyName -BearerToken $bearerToken
    } catch {
        Write-Host "Token retrieval error: $_" -ForegroundColor Red
        exit 1
    }
    Write-Host 'MFA cache token retrieved.' -ForegroundColor Green

    # --- Encrypt and patch the RDG file ---
    $encryptedToken = ConvertTo-RdcManPassword $mfaToken

    try {
        $count = Update-RdgMfaPasswords -RdgPath $rdgPath -EncryptedToken $encryptedToken
    } catch {
        Write-Host "Error updating RDG file: $_" -ForegroundColor Red
        exit 1
    }

    if ($count -eq 0) {
        Write-Host 'No /m connections found in the selected file — nothing was updated.' -ForegroundColor Yellow
    } else {
        Write-Host "Updated $count connection(s) in: $rdgPath" -ForegroundColor Green
        Write-Host 'Reload the file in RDC Manager to pick up the new token.' -ForegroundColor DarkGray
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIAuth
}
