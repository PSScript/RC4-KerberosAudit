# RC4-KerberosAudit

Windows Server 2025 Security Defaults Audit — SMB Signing, Kerberos RC4/AES, LDAP Signing, NTLM.

## Problem

Windows Server 2025 changes four security defaults simultaneously:

1. **SMB Signing** required for all connections (previously only SYSVOL/NETLOGON)
2. **Kerberos RC4** TGTs no longer issued by 2025 DCs
3. **LDAP Signing** enforced on new deployments
4. **NTLM** restrictions tightened

In mixed environments with older Domain Controllers and servers, these changes cause intermittent authentication failures, replication issues, and service outages. The symptoms are frequently misdiagnosed as image corruption or software defects.

A reinstall from a clean Server 2025 image reproduces the same behavior — because the defaults are by design, not a bug.

## Scripts

### Check-Server2025Defaults-v4.ps1

Full environment audit. Discovers server roles from AD, checks Kerberos encryption types, and validates SMB/LDAP/NTLM settings via WinRM.

**Three phases:**

| Phase | What | Requires |
|---|---|---|
| Phase 1 | AD role discovery (DC, Exchange, CA, Cluster, DFS, Hyper-V) | AD module or ADSI |
| Phase 1.5 | Kerberos encryption audit (msDS-SupportedEncryptionTypes) | AD module or ADSI |
| Phase 2 | Remote SMB/LDAP/NTLM/Kerberos policy check | WinRM |

**Parameters:**

| Parameter | Values | Default | Description |
|---|---|---|---|
| `-Scope` | DomainControllers, MemberServers, All | All | Which servers to check |
| `-KerberosScope` | DiscoveredOnly, AllServers, Full | DiscoveredOnly | Kerberos audit scope |
| `-SkipRemoteCheck` | Switch | — | Phase 1 + 1.5 only, no WinRM |
| `-ExportCsv` | Path | — | Additional CSV export path |

**Usage:**

```powershell
# Standard: all phases, discovered servers only
.\Check-Server2025Defaults-v4.ps1

# AD-only analysis, no WinRM (SOC-friendly)
.\Check-Server2025Defaults-v4.ps1 -SkipRemoteCheck

# Full domain scan (5000+ objects — coordinate with SOC)
.\Check-Server2025Defaults-v4.ps1 -KerberosScope Full

# DCs only with CSV export
.\Check-Server2025Defaults-v4.ps1 -Scope DomainControllers -ExportCsv C:\Temp\DC-Audit.csv
```

**Auto-generated reports** (C:\Temp\, semicolon delimiter):

| File | Content |
|---|---|
| `SMB_Kerberos_report_[ts].csv` | Main report: all servers with SMB/LDAP/Kerberos status |
| `..._KerberosAudit.csv` | Per-account encryption types with fix commands |
| `..._recommendations.csv` | Majority-based recommendations |
| `..._urgent_fix.csv` | Critical findings with PowerShell fix commands, sorted by priority |

Each finding includes the relevant GPO name, registry key, cmdlet, and AD attribute.

---

### Prove-RC4Usage.ps1

Proves whether RC4 Kerberos tickets are actively issued in the environment. Uses FilterXML for server-side event filtering — no O(n) performance issues on busy DCs.

**Eight checks:**

| Check | Event ID | What |
|---|---|---|
| 1 | 4768 | TGT encryption type distribution |
| 2 | 4769 | RC4 Service Tickets (server-side filtered) |
| 3 | 14, 4 | KDC encryption type errors |
| 3b | 4770 | RC4 Ticket Renewals (cache extension) |
| 3c | 4771 | Kerberos Pre-Auth failures (fallback chain start) |
| 5 | 4625 + 4740 | NTLM fallback failures + Lockout correlation (60s window) |
| 6 | 2887/2889/3039 | LDAP Signing + Channel Binding |
| 7 | AD | Account encryption types (msDS-SupportedEncryptionTypes) |

**Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `-Hours` | 24 | How many hours back to scan |
| `-MaxEvents` | 500 | Max events per check |
| `-ExportPath` | C:\Temp | CSV export folder |
| `-CountOnly` | off | Fast mode: counts only via wevtutil, no details |

**Usage:**

```powershell
# Standard: last 24 hours, max 500 events
.\Prove-RC4Usage.ps1

# Last 72 hours, more events
.\Prove-RC4Usage.ps1 -Hours 72 -MaxEvents 1000

# Fast count mode
.\Prove-RC4Usage.ps1 -CountOnly

# Last 7 days
.\Prove-RC4Usage.ps1 -Hours 168
```

**Performance:**

- **FilterXML**: Windows event engine filters server-side, not PowerShell
- **MaxEvents**: caps results, never reads entire log
- **XML parsing**: `[xml]$evt.ToXml()` instead of string regex on Message field
- **wevtutil**: even faster for `-CountOnly` mode

**Fallback chain correlation:**

The script detects Lockouts (4740) that occur within 60 seconds of a Kerberos Pre-Auth failure (4771) for the same account. This pattern indicates the Kerberos→NTLM→Lockout fallback chain — where a Kerberos encryption mismatch triggers NTLM fallback with stale credentials, resulting in account lockouts.

## Encryption Type Reference

| Value | Bitmask | Meaning | Server 2025 Risk |
|---|---|---|---|
| 0 / NULL | — | Follows domain default | Mid-2026: default changes to AES-only |
| 4 | RC4 only | Only RC4 | **Breaks immediately** on 2025 DC |
| 24 | AES128 + AES256 | AES only (target) | Safe |
| 28 | RC4 + AES128 + AES256 | Mixed | KDC may select RC4 |
| 31 | DES + RC4 + AES | Everything | DES broken, RC4 risky |

## GPO Reference

| Setting | GPO Path | Registry Key |
|---|---|---|
| SMB Server Signing | `Microsoft network server: Digitally sign communications (always)` | `Get-SmbServerConfiguration` |
| SMB Client Signing | `Microsoft network client: Digitally sign communications (always)` | `Get-SmbClientConfiguration` |
| Kerberos Encryption | `Network security: Configure encryption types allowed for Kerberos` | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes` |
| LDAP Signing | — | `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` |
| LDAP Channel Binding | — | `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` |
| NTLM Restriction | — | `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain` |

## Event ID Reference

| Area | Event ID | Log | Meaning |
|---|---|---|---|
| Kerberos | 4768 | Security | TGT issued — check Ticket Encryption Type |
| Kerberos | 4769 | Security | Service Ticket — check Ticket Encryption Type |
| Kerberos | 4770 | Security | Ticket Renewal — RC4 tickets stay alive longer |
| Kerberos | 4771 | Security | Pre-Auth Failed — fallback chain begins |
| Kerberos | 14 | System | KDC_ERR_ETYPE_NOSUPP — no matching encryption type |
| Kerberos | 4 | System/KDC | Client key not found |
| SMB | 1005 | SMBServer/Operational | Client rejected — no signing |
| SMB | 1006 | SMBServer/Operational | Client does not support signing |
| LDAP | 2886 | Directory Service | DC accepts unsigned binds (summary, every 24h) |
| LDAP | 2887 | Directory Service | Count of unsigned binds in last 24h |
| LDAP | 2889 | Directory Service | Per-client unsigned bind with IP |
| LDAP | 3039 | Directory Service | Client missing Channel Binding |
| Auth | 4625 | Security | Failed Logon — check AuthenticationPackageName |
| Auth | 4740 | Security | Account Lockout — check CallerComputer |

## References

- [SMB Signing Defaults Matrix (DSInternals)](https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/)
- [Detect and Remediate RC4 in Kerberos (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [What's New in Windows Server 2025 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025)
- [SMB Security Hardening (Microsoft Learn, DE)](https://learn.microsoft.com/de-de/windows-server/storage/file-server/smb-security-hardening)
- [Beyond RC4 for Windows Authentication (Microsoft Blog)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/)
- [Server 2025 DC: Avoid in Mixed Environments (Born's IT Blog)](https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/)
- [Server 2025 DC In-Place Upgrade (Frankys Web)](https://www.frankysweb.de/en/windows-server-2025-domain-controller-inplace-upgrade/)
- [SMB Security Hardening Blog (Microsoft TechCommunity)](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)

## Requirements

- PowerShell 5.1+
- Active Directory module (or ADSI fallback)
- Run on a Domain Controller for best results
- WinRM for Phase 2 remote checks

## License

MIT
