# SIAnable for RDCMan

A pair of PowerShell scripts that make [Remote Desktop Connection Manager (RDCMan)](https://learn.microsoft.com/en-us/sysinternals/downloads/rdcman) work with [CyberArk Secure Infrastructure Access (SIA)](https://www.cyberark.com/products/secure-infrastructure-access/).

## Scripts

| Script | Purpose |
|---|---|
| `SIAnable-for-RDCMan.ps1` | Converts an existing `.rdg` file into a SIA-enabled duplicate, rewriting all server connections to route through the CyberArk SIA gateway |
| `SIAuth-for-RDCMan.ps1` | Authenticates to CyberArk Identity, retrieves an MFA caching token from the DPA API, and writes it into every `/m` connection in a `.rdg` file |

## Requirements

- Windows PowerShell 5.1 or later
- [Remote Desktop Connection Manager](https://learn.microsoft.com/en-us/sysinternals/downloads/rdcman)
- A CyberArk SIA tenant with DPA enabled
- A CyberArk Identity account with MFA enrolled

## Configuration

Both scripts share a `sia_config.json` file stored alongside them. The file is created and updated automatically when you run either script. Fields:

| Field | Description |
|---|---|
| `TenantFriendlyName` | Your SIA tenant name (e.g. `pineapple`). Used to build `pineapple.rdp.cyberark.cloud` and `pineapple-userportal.cyberark.cloud` |
| `IdentityTenantId` | Your CyberArk Identity tenant ID (e.g. `AAP4212`). Used to build `AAP4212.id.cyberark.cloud` |
| `IspssUsername` | Your CyberArk Identity username (e.g. `user@example.com`) |
| `EnableMfaCache` | `true` to append `/m` to all connection strings, enabling MFA token caching |
| `TargetGroupName` | Display name of the root group in the output `.rdg` file |
| `SourceRdgPath` | Path to the source `.rdg` file used by `SIAnable` |
| `TargetRdgPath` | Path where `SIAnable` writes its output, and the default file `SIAuth` updates |

## SIAnable-for-RDCMan.ps1

Reads a source `.rdg` file and produces a new one where every server connection is rewritten to:

- Connect via `<tenant>.rdp.cyberark.cloud` as the RDP gateway
- Use a `secureaccess` command string as the RDP username, which the SIA client interprets to broker the connection
- Preserve the original group hierarchy

### Usage

```powershell
.\SIAnable-for-RDCMan.ps1
```

The script prompts for all settings on first run and saves them to `sia_config.json`. Subsequent runs show saved values in brackets — press Enter to keep them, type a new value to override, or type `B` to open a file browser.

### Connection string format

Each server's RDP username is set to:

```
secureaccess /i <IspssUsername> /s <TenantFriendlyName> /a <originalHostname> [/m]
```

The `/m` flag is included when `EnableMfaCache` is `true`. When present, the RDP client passes the password field to `secureaccess` as the MFA cache token rather than prompting for MFA interactively.

## SIAuth-for-RDCMan.ps1

Authenticates to CyberArk Identity, obtains a DPA RDP token, and writes it into the `<password>` field of every connection whose username contains `/m`. The password is DPAPI-encrypted so RDCMan can read it.

Run this periodically to refresh the token before it expires (tokens are typically valid for one hour).

### Usage

```powershell
.\SIAuth-for-RDCMan.ps1
```

Add `-DebugMode` to print every API request and response:

```powershell
.\SIAuth-for-RDCMan.ps1 -DebugMode
```

### Authentication flow

1. `POST /Security/StartAuthentication` — begins the session
2. Password challenge (`UP` mechanism) — prompts for your password
3. MFA challenge — presents available methods if more than one is enrolled; supports:
   - **OATH TOTP** (Google Authenticator, CyberArk Authenticator, etc.)
   - **SMS / Email OTP**
   - **Phone call**
   - **FIDO2 / YubiKey**
   - **RADIUS** (CyberArk MFA, Okta MFA)
4. On success, calls `POST /api/adb/sso/acquire` on the DPA userportal to retrieve the RDP token
5. DPAPI-encrypts the token and writes it to every matching credential entry in the selected `.rdg` file

### Supported credential locations

The script updates `/m` credentials stored in either:

- Inline `<logonCredentials>` blocks inside `<server>` elements (the format produced by `SIAnable`)
- Shared `<credentialsProfile>` blocks at file or group level (manually authored `.rdg` files)

### Notes

- Tokens are DPAPI-encrypted and tied to the current Windows user account. The `.rdg` file will only work when opened as the same user on the same machine.
- If `SIAuth` has not been run yet (or the token has expired), connections using `/m` will fail with an authentication error. Re-run `SIAuth` to refresh.
- The script updates all `/m` credentials it finds in the selected file regardless of tenant. If your file mixes connections from multiple tenants, run the script once per tenant against the appropriate file.
