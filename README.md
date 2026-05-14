# SIAnable

PowerShell scripts that make remote connection clients work with [CyberArk Secure Infrastructure Access (SIA)](https://www.cyberark.com/products/secure-infrastructure-access/).

## Scripts

### Remote Desktop Connection Manager (RDCMan)

| Script | Purpose |
|---|---|
| `SIAnable-for-RDCMan.ps1` | Converts an existing `.rdg` file into a SIA-enabled duplicate, rewriting all server connections to route through the CyberArk SIA gateway |
| `SIAuth-for-RDCMan.ps1` | Authenticates to CyberArk Identity, retrieves an MFA caching token from the SIA API, and writes it into every `/m` connection in a `.rdg` file |

### Royal TS

| Script | Purpose |
|---|---|
| `SIAnable-for-RoyalTS.ps1` | Converts an existing `.rtsz` document into a SIA-enabled duplicate, rewriting all RDP connections to route through the CyberArk SIA gateway |
| `SIAuth-for-RoyalTS.ps1` | Authenticates to CyberArk Identity, retrieves an MFA caching token from the SIA API, and writes it into every `/m` connection in a `.rtsz` document |

### MobaXterm

| Script | Purpose |
|---|---|
| `SIAnable-for-MobaXterm.ps1` | Converts existing MobaXterm SSH sessions into SIA-enabled duplicates prefixed with `_SIA`, written into a dedicated `CyberArk SIA Connections` bookmark folder in `MobaXterm.ini` |

### PuTTY

| Script | Purpose |
|---|---|
| `SIAnable-for-PuTTY.ps1` | Converts existing PuTTY SSH sessions (read from the registry) into SIA-enabled duplicates prefixed with `_SIA`, rewriting the hostname and username to route through the CyberArk SIA SSH gateway |
| `SIAuth-for-SSH.ps1` | Authenticates to CyberArk Identity, retrieves an SSH key from the SIA API, and stores it in `~\.ssh\` for use by the converted sessions |

## Requirements

- Windows PowerShell 5.1 or later
- A CyberArk SIA tenant
- A CyberArk Identity account with MFA enrolled
- **RDCMan scripts:** [Remote Desktop Connection Manager](https://learn.microsoft.com/en-us/sysinternals/downloads/rdcman)
- **Royal TS scripts:** [Royal TS v7](https://www.royalapps.com/ts/win/download) — the `RoyalDocument.PowerShell` module is installed automatically on first run
- **MobaXterm scripts:** [MobaXterm](https://mobaxterm.mobatek.net/) with at least one saved SSH session
- **PuTTY scripts:** [PuTTY](https://www.putty.org/) installed with at least one saved SSH session

## Configuration

All scripts share a single `sia_config.json` file stored alongside them. The file is created and updated automatically when you run any script. Fields:

| Field | Description |
|---|---|
| `TenantFriendlyName` | Your SIA tenant name (e.g. `pineapple`). Used to build `pineapple.rdp.cyberark.cloud` and `pineapple-userportal.cyberark.cloud` |
| `IdentityTenantId` | Your CyberArk Identity tenant ID (e.g. `AAP4212`). Used to build `AAP4212.id.cyberark.cloud` |
| `IspssUsername` | Your CyberArk Identity username (e.g. `user@example.com`) |
| `EnableMfaCache` | `true` to append `/m` to all connection strings, enabling MFA token caching |
| `TargetGroupName` | Display name of the root group in the output `.rdg` file (RDCMan only) |
| `SourceRdgPath` | Path to the source `.rdg` file |
| `TargetRdgPath` | Path where `SIAnable-for-RDCMan` writes its output, and the default file `SIAuth-for-RDCMan` updates |
| `SourceRtszPath` | Path to the source `.rtsz` document |
| `TargetRtszPath` | Path where `SIAnable-for-RoyalTS` writes its output, and the default file `SIAuth-for-RoyalTS` updates |
| `SshKeyFormat` | SSH key format for PuTTY scripts: `ppk` (native PuTTY format) or `openssh` |

---

## RDCMan scripts

### SIAnable-for-RDCMan.ps1

Reads a source `.rdg` file and produces a new one where every server connection is rewritten to:

- Connect via `<tenant>.rdp.cyberark.cloud` as the RDP gateway
- Use a `secureaccess` command string as the RDP username, which the SIA client interprets to broker the connection
- Preserve the original group hierarchy

```powershell
.\SIAnable-for-RDCMan.ps1
```

The script prompts for all settings on first run and saves them to `sia_config.json`. Subsequent runs show saved values in brackets — press Enter to keep them, type a new value to override, or type `B` to open a file browser.

### SIAuth-for-RDCMan.ps1

Authenticates to CyberArk Identity, obtains an SIA RDP token, and writes it into the `<password>` field of every connection whose username contains `/m`. The password is DPAPI-encrypted so RDCMan can read it.

```powershell
.\SIAuth-for-RDCMan.ps1
.\SIAuth-for-RDCMan.ps1 -DebugMode   # print every API request and response
```

Supports credentials stored in either inline `<logonCredentials>` blocks (the format produced by `SIAnable-for-RDCMan`) or shared `<credentialsProfile>` blocks in manually authored `.rdg` files.

> **Note:** Tokens are DPAPI-encrypted and tied to the current Windows user account. The `.rdg` file will only work when opened as the same user on the same machine.

---

## Royal TS scripts

### SIAnable-for-RoyalTS.ps1

Reads a source `.rtsz` document and produces a new one where every RDP connection is rewritten to route through the CyberArk SIA gateway. Folder hierarchy is preserved. Non-RDP connection types (SSH, web, etc.) are omitted from the output.

```powershell
.\SIAnable-for-RoyalTS.ps1
```

The output document contains:

- A shared gateway credential object (`SIA_GW_<tenant>`) used by all connections for gateway authentication
- Per-connection inline credentials with the `secureaccess` command string as the username

### SIAuth-for-RoyalTS.ps1

Authenticates to CyberArk Identity, obtains an SIA RDP token, and writes it into the `CredentialPassword` of every RDP connection whose username contains `/m`. Royal TS handles password encryption internally — no DPAPI call is required.

```powershell
.\SIAuth-for-RoyalTS.ps1
.\SIAuth-for-RoyalTS.ps1 -DebugMode   # print every API request and response
```

---

## Authentication flow (SIAuth scripts)

Both `SIAuth` scripts share the same authentication logic:

1. `POST /Security/StartAuthentication` — begins the session
2. Password challenge (`UP` mechanism) — prompts for your password
3. MFA challenge — presents available methods if more than one is enrolled; supports:
   - **OATH TOTP** (Google Authenticator, CyberArk Authenticator, etc.)
   - **SMS / Email OTP**
   - **Phone call**
   - **FIDO2 / YubiKey**
   - **RADIUS** (CyberArk MFA, Okta MFA)
4. On success, calls `POST /api/adb/sso/acquire` on the SIA userportal to retrieve the RDP token
5. Writes the token to every `/m` credential entry in the selected file

> Tokens are typically valid for one hour. Re-run the relevant `SIAuth` script to refresh before they expire. All `/m` credentials in the selected file are updated regardless of tenant — if your file mixes connections from multiple tenants, run once per tenant against the appropriate file.

## RDP connection string format

```
secureaccess /i <IspssUsername> /s <TenantFriendlyName> /a <originalHostname> [/m]
```

The `/m` flag is included when `EnableMfaCache` is `true`. When present, the connection passes the stored password to `secureaccess` as the MFA cache token rather than prompting for MFA interactively on each connection.

---

## PuTTY scripts

### SIAnable-for-PuTTY.ps1

Reads all SSH sessions from the PuTTY registry (`HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions`), skips any already prefixed with `_SIA`, and creates a `_SIA<original>` duplicate for each one. Sessions are prefixed with `_SIA` so they sort to the top of the PuTTY session list.

```powershell
.\SIAnable-for-PuTTY.ps1
```

Each converted session has:
- **Host** set to `<tenant>.ssh.cyberark.cloud`
- **Username** set to `<IspssUsername>#<tenant>@<originalHostname>` — PuTTY appends `@<host>` to produce the full SSH target the SIA gateway expects
- **Private key file** set to the SSH key path (when MFA caching is enabled)

All other session settings (port, terminal settings, proxy, etc.) are copied verbatim from the source.

Only sessions using the SSH protocol are converted. Non-SSH sessions (Telnet, Serial, etc.) are skipped.

### SIAuth-for-SSH.ps1

Authenticates to CyberArk Identity and retrieves an SSH key from the SIA API, storing it at `~\.ssh\cyberark_sia_<tenant>[.ppk]`. The `_SIA` sessions created by `SIAnable-for-PuTTY` are pre-configured to load the key from this path automatically.

```powershell
.\SIAuth-for-SSH.ps1
.\SIAuth-for-SSH.ps1 -DebugMode   # print every API request and response
```

The key format (`ppk` or `openssh`) is set during `SIAnable-for-PuTTY` configuration and saved to `sia_config.json`. Use `ppk` for native PuTTY sessions; use `openssh` for other SSH clients (OpenSSH, WinSCP, etc.) that read from `~\.ssh\`.

### SSH connection string format

```
<IspssUsername>#<TenantFriendlyName>@<originalHostname>@<TenantFriendlyName>.ssh.cyberark.cloud
```

The portion before the final `@` is the SSH username; the portion after is the gateway hostname.
