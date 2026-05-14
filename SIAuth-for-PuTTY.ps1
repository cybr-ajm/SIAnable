#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticates to CyberArk SIA and retrieves an SSH key, storing it in the user's .ssh folder.
.DESCRIPTION
    Reads tenant/user settings from sia_config.json, authenticates via CyberArk Identity,
    then calls the SIA SSH key API to retrieve a key in the configured format (ppk or openssh)
    and writes it to ~\.ssh\cyberark_sia_<tenant>[.ppk].
    PuTTY sessions created by SIAnable-for-PuTTY are pre-configured to use this file path.
#>

[CmdletBinding()]
param(
    [switch]$DebugMode
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ConfigFile       = Join-Path $PSScriptRoot 'sia_config.json'
$Script:DebugMode = $DebugMode.IsPresent

# ---------------------------------------------------------------------------
# Shared helper — must match SIAnable-for-PuTTY exactly
# ---------------------------------------------------------------------------

function Get-SshKeyPath {
    param([string]$Tenant, [string]$Format)
    $ext = if ($Format -eq 'ppk') { '.ppk' } else { '' }
    Join-Path $env:USERPROFILE ".ssh\cyberark_sia_$Tenant$ext"
}

# ---------------------------------------------------------------------------
# Config loading
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

# ---------------------------------------------------------------------------
# Debug trace helper
# ---------------------------------------------------------------------------

function Trace-ApiCall {
    param([string]$Method, [string]$Uri, [string]$Body, $Response, [switch]$RedactAnswer)
    if (-not $Script:DebugMode) { return }

    if ($Body) {
        $displayBody = if ($RedactAnswer) {
            $Body -replace '("Answer"\s*:\s*")[^"]*"', '$1****"'
        } else { $Body }
        Write-Host "  [DBG] -> $Method $Uri" -ForegroundColor DarkCyan
        Write-Host "         Req : $displayBody" -ForegroundColor DarkCyan
    } elseif ($Uri) {
        Write-Host "  [DBG] -> $Method $Uri" -ForegroundColor DarkCyan
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
        Trace-ApiCall -Method POST -Uri "$idpBase/Security/StartAuthentication" -Body $startBody -Response $startResp
    } catch {
        throw "StartAuthentication request failed: $_"
    }

    if ($startResp.success -ne $true) { throw "StartAuthentication failed: $($startResp.Message)" }

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
            do { $pick = Read-Host "Select method (1-$($mechanisms.Count))" } `
                while ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $mechanisms.Count)
            $mechanisms[[int]$pick - 1]
        }

        $mechId        = $mechanism.MechanismId
        $prompt        = if ($mechanism.PromptMechChosen) { $mechanism.PromptMechChosen } else { $mechanism.PromptSelectMech }
        $needsOobStart = $mechanism.AnswerType -in @('StartOob', 'StartTextOob')
        $needsText     = $mechanism.AnswerType -in @('Text', 'StartTextOob')

        if (-not $needsOobStart) {
            $answer = if ($mechanism.Name -eq 'UP') {
                $ss = Read-Host $prompt -AsSecureString
                [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
            } else { Read-Host $prompt }
            $body = @{ SessionId = $sessionId; MechanismId = $mechId; Action = 'Answer'; Answer = $answer } | ConvertTo-Json
            try {
                $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                               -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                Trace-ApiCall -Method POST -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp -RedactAnswer:($mechanism.Name -eq 'UP')
            } catch { throw "AdvanceAuthentication failed: $_" }
            if ($advResp.success -eq $false) { throw "CyberArk rejected the response: $($advResp.Message)" }
        } else {
            $body = @{ SessionId = $sessionId; MechanismId = $mechId; Action = 'StartOOB'; Answer = '' } | ConvertTo-Json
            try {
                $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                               -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                Trace-ApiCall -Method POST -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp
            } catch { throw "AdvanceAuthentication (StartOOB) failed: $_" }
            if ($advResp.success -eq $false) { throw "CyberArk rejected StartOOB: $($advResp.Message)" }

            if ($advResp.Result.Summary -eq 'OobPending') {
                if (-not $needsText) { Write-Host "$prompt — approve on your device..." -ForegroundColor Yellow }
                else { Write-Host '  Waiting for challenge to initialise...' -ForegroundColor DarkGray }

                $deadline = (Get-Date).AddSeconds(360)
                while ($advResp.Result.Summary -eq 'OobPending' -and (Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 500
                    $body = @{ SessionId = $sessionId; MechanismId = $mechId; Action = 'Poll'; Answer = '' } | ConvertTo-Json
                    try {
                        $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                                       -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                        Trace-ApiCall -Method POST -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp
                    } catch { throw "OOB poll failed: $_" }
                    if ($advResp.success -eq $false) { throw "CyberArk rejected the OOB attempt: $($advResp.Message)" }
                    if (-not $needsText -and $advResp.Result.Summary -eq 'OobPending') {
                        Write-Host '  Still waiting...' -ForegroundColor DarkGray
                    }
                }
            }

            if ($needsText -and $advResp.Result.Summary -ne 'LoginSuccess') {
                $answer = Read-Host $prompt
                $body = @{ SessionId = $sessionId; MechanismId = $mechId; Action = 'Answer'; Answer = $answer } | ConvertTo-Json
                try {
                    $advResp = Invoke-RestMethod -Uri "$idpBase/Security/AdvanceAuthentication" `
                                   -Method Post -Headers $jsonHeaders -Body $body -WebSession $webSession -ErrorAction Stop
                    Trace-ApiCall -Method POST -Uri "$idpBase/Security/AdvanceAuthentication" -Body $body -Response $advResp
                } catch { throw "AdvanceAuthentication (Answer) failed: $_" }
                if ($advResp.success -eq $false) { throw "CyberArk rejected the response: $($advResp.Message)" }
            }
        }

        switch ($advResp.Result.Summary) {
            'LoginSuccess' {
                $platformToken = if ($advResp.Result.Token) { $advResp.Result.Token }
                                 elseif ($advResp.Result.Auth) { $advResp.Result.Auth }
                                 else { $advResp.Result.PlatformToken }
            }
            'LoginFailure' { throw "Authentication failed: $($advResp.Result.Message)" }
            { $_ -in 'NewPackage', 'StartNextChallenge', 'Continue' } { }
            default { throw "Unexpected authentication response: $($advResp.Result.Summary)" }
        }

        if ($platformToken) { break }
    }

    if (-not $platformToken) { throw 'Authentication completed but no token was returned.' }
    return $platformToken
}

# ---------------------------------------------------------------------------
# Retrieve the SIA SSH key
# ---------------------------------------------------------------------------

function Get-SiaSshKey {
    param([string]$Tenant, [string]$BearerToken, [string]$Format)

    $uri     = "https://$Tenant.dpa.cyberark.cloud/api/ssh/sso/key?format=$Format"
    $headers = @{
        'Authorization' = "Bearer $BearerToken"
        'Accept'        = 'application/x-pem-file, application/vnd.putty.ppk, application/json'
    }

    if ($Script:DebugMode) {
        Write-Host "  [DBG] -> GET $uri" -ForegroundColor DarkCyan
        Write-Host "         Headers:" -ForegroundColor DarkCyan
        $headers.GetEnumerator() | ForEach-Object {
            $val = if ($_.Key -eq 'Authorization') { 'Bearer [...token...]' } else { $_.Value }
            Write-Host "           $($_.Key): $val" -ForegroundColor DarkCyan
        }
    }

    try {
        $resp = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
    } catch {
        if ($Script:DebugMode -and $_.Exception.Response) {
            $errBody = $_.Exception.Response.GetResponseStream()
            $reader  = New-Object System.IO.StreamReader($errBody)
            Write-Host "  [DBG] Error response body: $($reader.ReadToEnd())" -ForegroundColor Red
        }
        throw "SSH key request failed: $_"
    }

    # Invoke-WebRequest returns a byte[] for non-text Content-Types like application/vnd.putty.ppk.
    # Decode to string regardless so the caller always receives usable text.
    $keyText = if ($resp.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($resp.Content)
    } else {
        $resp.Content
    }

    if ($Script:DebugMode) {
        Write-Host "         Status       : $($resp.StatusCode) $($resp.StatusDescription)" -ForegroundColor DarkYellow
        Write-Host "         Content-Type : $($resp.Headers['Content-Type'])" -ForegroundColor DarkYellow
        Write-Host "         Body:" -ForegroundColor DarkYellow
        Write-Host $keyText -ForegroundColor DarkYellow
    }

    if (-not $keyText) { throw 'SIA returned an empty SSH key response.' }
    return $keyText
}

# ---------------------------------------------------------------------------
# Write the key to disk
# ---------------------------------------------------------------------------

function Save-SshKey {
    param([string]$KeyContent, [string]$KeyPath)

    $dir = Split-Path $KeyPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item $dir -ItemType Directory -Force | Out-Null
    }

    Set-Content -Path $KeyPath -Value $KeyContent -Encoding UTF8 -NoNewline -Force
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

function Invoke-SIAuthPuTTY {
    $config = Get-Config

    if (-not $config.TenantFriendlyName -or -not $config.IdentityTenantId -or -not $config.IspssUsername) {
        Write-Host 'No saved tenant/user config found. Run SIAnable-for-PuTTY.ps1 first to set it up.' -ForegroundColor Red
        exit 1
    }

    $keyPath = Get-SshKeyPath -Tenant $config.TenantFriendlyName -Format $config.SshKeyFormat

    Write-Host ''
    Write-Host '=== CyberArk SIA SSH Key Refresh ===' -ForegroundColor Cyan
    Write-Host "  Tenant          : $($config.TenantFriendlyName)"
    Write-Host "  Identity tenant : $($config.IdentityTenantId)"
    Write-Host "  User            : $($config.IspssUsername)"
    Write-Host "  Key format      : $($config.SshKeyFormat)"
    Write-Host "  Key destination : $keyPath"
    Write-Host ''

    # --- Authenticate ---
    try {
        $bearerToken = Invoke-CyberArkIdentityAuth -IdentityTenantId $config.IdentityTenantId `
                                                   -Username $config.IspssUsername
    } catch {
        Write-Host "Authentication error: $_" -ForegroundColor Red; exit 1
    }
    Write-Host 'Authentication successful.' -ForegroundColor Green

    # --- Retrieve SSH key ---
    try {
        $keyContent = Get-SiaSshKey -Tenant $config.TenantFriendlyName `
                                    -BearerToken $bearerToken `
                                    -Format $config.SshKeyFormat
    } catch {
        Write-Host "SSH key retrieval error: $_" -ForegroundColor Red; exit 1
    }
    Write-Host 'SSH key retrieved.' -ForegroundColor Green

    # --- Save to disk ---
    try {
        Save-SshKey -KeyContent $keyContent -KeyPath $keyPath
    } catch {
        Write-Host "Error saving SSH key: $_" -ForegroundColor Red; exit 1
    }

    Write-Host "SSH key written to: $keyPath" -ForegroundColor Green
    if ($config.SshKeyFormat -eq 'ppk') {
        Write-Host 'PuTTY _SIA sessions are configured to use this key automatically.' -ForegroundColor DarkGray
    } else {
        Write-Host 'OpenSSH key stored. Ensure your SSH client is configured to use it.' -ForegroundColor DarkGray
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SIAuthPuTTY
}
