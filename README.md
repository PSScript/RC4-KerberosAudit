# RC4-KerberosAudit

Windows Server 2025 Sicherheits-Defaults Audit — SMB Signierung, Kerberos RC4/AES, LDAP Signierung, NTLM.

[English version](README_EN.md)

## Problem

Windows Server 2025 ändert vier Sicherheits-Defaults gleichzeitig:

1. **SMB Signierung** wird für alle Verbindungen erzwungen (bisher nur SYSVOL/NETLOGON)
2. **Kerberos RC4** TGTs werden von 2025 DCs nicht mehr ausgestellt
3. **LDAP Signierung** wird bei Neuinstallationen erzwungen
4. **NTLM** Einschränkungen werden verschärft

In gemischten Umgebungen mit älteren Domain Controllern und Servern führen diese Änderungen zu sporadischen Anmeldefehlern, Replikationsproblemen und Dienstausfällen. Die Symptome werden häufig als Image-Korruption oder Softwaredefekt fehlinterpretiert.

Eine Neuinstallation mit einem neuen Server-2025-Image reproduziert dasselbe Verhalten — die geänderten Defaults sind beabsichtigt, kein Bug.

## Skripte

### Check-Server2025Defaults-v4.ps1

Vollständiges Umgebungs-Audit. Erkennt Serverrollen aus AD, prüft Kerberos-Verschlüsselungstypen und validiert SMB/LDAP/NTLM-Einstellungen per WinRM.

**Drei Phasen:**

| Phase | Was | Voraussetzung |
|---|---|---|
| Phase 1 | AD-Rollenerkennung (DC, Exchange, CA, Cluster, DFS, Hyper-V) | AD-Modul oder ADSI |
| Phase 1.5 | Kerberos-Verschlüsselungs-Audit (msDS-SupportedEncryptionTypes) | AD-Modul oder ADSI |
| Phase 2 | Remote SMB/LDAP/NTLM/Kerberos Policy-Prüfung | WinRM |

**Parameter:**

| Parameter | Werte | Standard | Beschreibung |
|---|---|---|---|
| `-Scope` | DomainControllers, MemberServers, All | All | Welche Server geprüft werden |
| `-KerberosScope` | DiscoveredOnly, AllServers, Full | DiscoveredOnly | Umfang der Kerberos-Prüfung |
| `-SkipRemoteCheck` | Switch | — | Nur Phase 1 + 1.5, kein WinRM |
| `-ExportCsv` | Pfad | — | Zusätzlicher CSV-Export |

**Aufruf:**

```powershell
# Standard: alle Phasen, nur erkannte Server
.\Check-Server2025Defaults-v4.ps1

# Nur AD-Analyse, kein WinRM (SOC-freundlich)
.\Check-Server2025Defaults-v4.ps1 -SkipRemoteCheck

# Gesamte Domäne (5000+ Objekte — mit SOC abstimmen)
.\Check-Server2025Defaults-v4.ps1 -KerberosScope Full

# Nur DCs mit CSV-Export
.\Check-Server2025Defaults-v4.ps1 -Scope DomainControllers -ExportCsv C:\Temp\DC-Audit.csv
```

**KerberosScope im Detail:**

| Scope | Prüft | Typische Objektanzahl |
|---|---|---|
| DiscoveredOnly | Nur Server aus Phase 1 (DC, Exchange, CA, Cluster, DFS, HyperV) | ~100–200 |
| AllServers | Alle Computer-Accounts mit OperatingSystem *Server* | ~300–500 |
| Full | Gesamte Domäne inkl. Service Accounts, gMSAs, Trusts | ~5.000+ |

**Automatisch erzeugte Reports** (C:\Temp\, Semikolon-Trennzeichen):

| Datei | Inhalt |
|---|---|
| `SMB_Kerberos_report_[ts].csv` | Hauptreport: alle Server mit SMB/LDAP/Kerberos-Status |
| `..._KerberosAudit.csv` | Verschlüsselungstypen pro Account mit Fix-Befehlen |
| `..._recommendations.csv` | Mehrheitsbasierte Empfehlungen |
| `..._urgent_fix.csv` | Kritische Befunde mit PowerShell Fix-Befehlen, nach Priorität sortiert |

Jedes Finding enthält den zugehörigen GPO-Namen, Registry-Schlüssel, Cmdlet und das AD-Attribut.

---

### Prove-RC4Usage.ps1

Prüft ob RC4 Kerberos-Tickets aktiv in der Umgebung ausgestellt werden. Verwendet FilterXML für serverseitige Event-Filterung — keine O(n)-Probleme auf ausgelasteten DCs.

**Acht Prüfungen:**

| Check | Event ID | Was |
|---|---|---|
| 1 | 4768 | TGT Verschlüsselungstyp-Verteilung |
| 2 | 4769 | RC4 Service Tickets (serverseitig gefiltert) |
| 3 | 14, 4 | KDC Verschlüsselungstyp-Fehler |
| 3b | 4770 | RC4 Ticket Renewals (Cache-Verlängerung) |
| 3c | 4771 | Kerberos Pre-Auth Fehler (Beginn Fallback-Kette) |
| 5 | 4625 + 4740 | NTLM Fallback Fehler + Lockout-Korrelation (60s-Fenster) |
| 6 | 2887/2889/3039 | LDAP Signierung + Channel Binding |
| 7 | AD | Account-Verschlüsselungstypen (msDS-SupportedEncryptionTypes) |

**Parameter:**

| Parameter | Standard | Beschreibung |
|---|---|---|
| `-Hours` | 24 | Wie viele Stunden zurück geprüft wird |
| `-MaxEvents` | 500 | Maximale Events pro Prüfung |
| `-ExportPath` | C:\Temp | Zielordner für CSV-Exports |
| `-CountOnly` | aus | Schnellmodus: nur Zählung per wevtutil, keine Details |

**Aufruf:**

```powershell
# Standard: letzte 24 Stunden, max 500 Events
.\Prove-RC4Usage.ps1

# Letzte 72 Stunden, mehr Events
.\Prove-RC4Usage.ps1 -Hours 72 -MaxEvents 1000

# Schnellmodus: nur Zählung
.\Prove-RC4Usage.ps1 -CountOnly

# Letzte 7 Tage
.\Prove-RC4Usage.ps1 -Hours 168
```

**Performance:**

- **FilterXML**: Windows Event Engine filtert serverseitig, nicht PowerShell
- **MaxEvents**: begrenzt Ergebnismenge, liest nie das gesamte Log
- **XML-Parsing**: `[xml]$evt.ToXml()` statt String-Regex auf dem Message-Feld
- **wevtutil**: noch schneller im `-CountOnly` Modus

**Fallback-Ketten-Korrelation:**

Das Skript erkennt Lockouts (4740) die innerhalb von 60 Sekunden nach einem Kerberos Pre-Auth Fehler (4771) für denselben Account auftreten. Dieses Muster deutet auf die Kerberos→NTLM→Lockout Fallback-Kette hin: ein Kerberos-Verschlüsselungsproblem löst einen NTLM-Fallback mit veralteten Credentials aus, was zur Kontosperrung führt.

**Erzeugte Reports:**

| Datei | Inhalt |
|---|---|
| `RC4_Proof_TGT_[ts].csv` | Alle TGT-Events mit Verschlüsselungstyp, Account, Client-IP |
| `RC4_Proof_SvcTickets_[ts].csv` | Alle RC4 Service Tickets mit Dienst und Account |
| `RC4_Proof_Renewals_[ts].csv` | RC4 Ticket Renewals (Cache-Verlängerung) |
| `RC4_Proof_PreAuth_[ts].csv` | Kerberos Pre-Auth Fehler mit Status-Code |
| `RC4_Proof_LogonFails_[ts].csv` | Fehlgeschlagene Anmeldungen mit Auth-Paket |
| `RC4_Proof_Lockouts_[ts].csv` | Kontosperrungen mit Caller Computer |
| `RC4_Proof_Korrelation_[ts].csv` | Lockouts die innerhalb 60s nach Kerberos-Fehler auftreten |
| `RC4_Proof_UnsignedLDAP_[ts].csv` | LDAP-Clients mit unsigniertem Bind |
| `RC4_Proof_URGENT_[ts].csv` | Zusammengefasste RC4-Nutzer mit Fix-Befehlen |

---

### Discover-RC4Environment.ps1

Erkennt RC4-anfällige Systeme in heterogenen Umgebungen und korreliert Kerberos-Events mit Anmeldefehlern. Ergänzung zu den beiden Audit-Skripten, Fokus auf Citrix, Igel, VMware, Linux und Delegation.

**Vier Phasen:**

| Phase | Was |
|---|---|
| 1. AD-Discovery | Citrix (StoreFront/DDC/VDA/NetScaler), Igel, Non-Windows (Linux/macOS/VMware/Appliances), Delegation-Accounts |
| 2. GPO-Analyse | Kerberos Encryption Policy auf dem DC |
| 3. Event-Korrelation | RC4-Tickets (4769/4770) → Pre-Auth (4771) → Failed Logon (4625) → Lockout (4740), 120s-Fenster |
| 4. Reporting | Excel mit Highlighting, CSVs pro Kategorie, ZIP, optionale E-Mail |

**Parameter:**

| Parameter | Standard | Beschreibung |
|---|---|---|
| `-Hours` | 24 | Event-Log Zeitraum |
| `-MaxEvents` | 1000 | Max Events pro Abfrage |
| `-ReportPath` | C:\Temp | Zielordner |
| `-SkipEvents` | aus | Nur AD-Discovery, keine Event-Logs |
| `-SendMail` | aus | ZIP per E-Mail versenden |
| `-MailTo` | — | Empfänger |
| `-SmtpServer` | — | SMTP-Server |

**Aufruf:**

```powershell
# Standard: Discovery + Events der letzten 24h
.\Discover-RC4Environment.ps1

# Nur AD-Discovery, keine Events
.\Discover-RC4Environment.ps1 -SkipEvents

# 72 Stunden, mit E-Mail-Versand
.\Discover-RC4Environment.ps1 -Hours 72 -SendMail -MailTo "team@example.com" -SmtpServer "mail.example.com"
```

**Erzeugte Reports** (Ordner `RC4_Discovery_[timestamp]` + ZIP):

| Datei / Sheet | Inhalt |
|---|---|
| Citrix | StoreFront, DDC, VDA, NetScaler, Service Accounts mit EncType + Fix |
| Igel | Thin Clients mit EncType + Firmware-Hinweis |
| NonWindows | Linux, macOS, VMware, Appliances mit Risiko-Bewertung |
| Delegation | Constrained/Unconstrained Delegation mit DelegateTo-Zielen |
| GPO_Policy | Aktuelle Kerberos GPO mit Empfehlung |
| RC4_Tickets | RC4 Service Tickets mit System-Zuordnung |
| Korrelation | Lockouts innerhalb 120s nach Kerberos-Fehler |
| LogonFails | Fehlgeschlagene Anmeldungen mit Auth-Paket und Workstation |

**Excel-Highlighting** (benötigt `ImportExcel`-Modul):

- RC4_ONLY → Rot
- RC4_AES → Gelb
- AES_ONLY → Grün
- Unconstrained Delegation → Rot
- Ohne ImportExcel: automatischer CSV-Fallback

**Voraussetzung:** `Install-Module ImportExcel -Scope CurrentUser` (optional, CSV funktioniert immer)

## Verschlüsselungstypen-Referenz

| Wert | Bitmask | Bedeutung | Server 2025 Risiko |
|---|---|---|---|
| 0 / NULL | — | Folgt Domain-Default | Mitte 2026: Default wird AES-only |
| 4 | RC4 only | Nur RC4 | **Bricht sofort** auf 2025 DC |
| 24 | AES128 + AES256 | Nur AES (Zielwert) | Sicher |
| 28 | RC4 + AES128 + AES256 | Gemischt | KDC kann RC4 wählen |
| 31 | DES + RC4 + AES | Alles | DES gebrochen, RC4 riskant |

## GPO-Referenz

| Einstellung | GPO-Pfad | Registry / Cmdlet |
|---|---|---|
| SMB Server Signierung | `Microsoft network server: Digitally sign communications (always)` | `Get-SmbServerConfiguration` |
| SMB Client Signierung | `Microsoft network client: Digitally sign communications (always)` | `Get-SmbClientConfiguration` |
| Kerberos Verschlüsselung | `Network security: Configure encryption types allowed for Kerberos` | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes` |
| LDAP Signierung | — | `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` |
| LDAP Channel Binding | — | `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` |
| NTLM Einschränkung | — | `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain` |

## Event ID Referenz

| Bereich | Event ID | Log | Bedeutung |
|---|---|---|---|
| Kerberos | 4768 | Security | TGT ausgestellt — Ticket Encryption Type prüfen |
| Kerberos | 4769 | Security | Service Ticket — Ticket Encryption Type prüfen |
| Kerberos | 4770 | Security | Ticket Renewal — RC4-Tickets leben länger durch Verlängerung |
| Kerberos | 4771 | Security | Pre-Auth fehlgeschlagen — Beginn der Fallback-Kette |
| Kerberos | 14 | System | KDC_ERR_ETYPE_NOSUPP — kein passender Verschlüsselungstyp |
| Kerberos | 4 | System/KDC | Client-Key nicht gefunden |
| SMB | 1005 | SMBServer/Operational | Client abgelehnt — keine Signierung |
| SMB | 1006 | SMBServer/Operational | Client unterstützt keine Signierung |
| LDAP | 2886 | Directory Service | DC akzeptiert noch unsigned Binds (Zusammenfassung, alle 24h) |
| LDAP | 2887 | Directory Service | Anzahl unsigned Binds in den letzten 24h |
| LDAP | 2889 | Directory Service | Unsigned Bind pro Client mit IP |
| LDAP | 3039 | Directory Service | Client ohne Channel Binding |
| Auth | 4625 | Security | Fehlgeschlagene Anmeldung — AuthenticationPackageName prüfen |
| Auth | 4740 | Security | Kontosperrung — CallerComputer prüfen |

## Referenzen

- [SMB Signierung Defaults Matrix (DSInternals)](https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/)
- [Kerberos RC4 erkennen und beheben (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Neuerungen in Windows Server 2025 (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025)
- [SMB-Sicherheitshärtung (Microsoft Learn, DE)](https://learn.microsoft.com/de-de/windows-server/storage/file-server/smb-security-hardening)
- [Beyond RC4 for Windows Authentication (Microsoft Blog)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/)
- [Server 2025 als DC: Finger weg bei gemischten Umgebungen (Borns IT-Blog)](https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/)
- [Server 2025 DC In-Place Upgrade (Frankys Web)](https://www.frankysweb.de/en/windows-server-2025-domain-controller-inplace-upgrade/)
- [SMB Security Hardening Blog (Microsoft TechCommunity)](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [RC4-Abschaltung Mitte 2026 (Borns IT-Blog)](https://borncity.com/blog/2025/12/18/windows-authentifizierung-microsoft-kappt-rc4-mitte-2025/)

## Voraussetzungen

- PowerShell 5.1+
- Active Directory Modul (oder ADSI-Fallback)
- Ausführung auf einem Domain Controller für optimale Ergebnisse
- WinRM für Phase 2 Remote-Prüfungen

## Lizenz

MIT
