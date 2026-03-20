# RC4-KerberosAudit — Nutzungsanleitung

Vier Skripte für die Analyse und Bewertung von Kerberos RC4-Risiken bei der Einführung von Windows Server 2025 in gemischte Umgebungen.

## Übersicht

| Skript | Zweck | Läuft auf | Braucht AD? | Braucht WinRM? |
|---|---|---|---|---|
| `Check-Server2025Defaults-v4.ps1` | SMB Signing, Kerberos EncType, LDAP, NTLM pro Server | DC | Ja | Ja (Phase 2) |
| `Prove-RC4Usage.ps1` | Beweis: welche RC4-Tickets fließen (Event-Log) | DC | Nein | Nein |
| `Discover-RC4Environment.ps1` | Citrix/Igel/Linux/Delegation + Kreuzprüfung | DC oder Workstation | Ja (Phase 1) | Nein |
| `New-RC4Report.ps1` | Management-Report (XLSX + HTML) aus CSVs | Beliebig | Nein | Nein |

## Workflow

```
Phase 1: Daten sammeln (auf dem DC)
  ├── Check-Server2025Defaults-v4.ps1    → SMB/LDAP/Kerberos CSVs
  ├── Prove-RC4Usage.ps1                 → RC4-Ticket-Beweis CSVs
  └── Discover-RC4Environment.ps1        → Discovery + Event-Korrelation CSVs

Phase 2: Ergebnisse kopieren
  └── CSVs/ZIPs auf Admin-Workstation kopieren

Phase 3: Bewerten (auf Workstation, ohne DC-Zugriff)
  ├── Discover-RC4Environment.ps1 -ReassessFrom <pfad>   → Kreuzprüfung
  └── New-RC4Report.ps1 -ReportPath <pfad>               → XLSX + HTML Report

Phase 4: Beheben
  └── Urgent Fixes aus dem Report umsetzen
```

---

## Check-Server2025Defaults-v4.ps1

Audit von SMB Signing, Kerberos Encryption, LDAP Signing und NTLM Restrictions pro Server.

### Syntax

```powershell
.\Check-Server2025Defaults-v4.ps1
    [-Scope <DomainControllers|MemberServers|All>]
    [-KerberosScope <DiscoveredOnly|AllServers|Full>]
    [-SkipRemoteCheck]
    [-ExportCsv <Pfad>]
```

### Parameter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `-Scope` | `All` | Welche Systeme geprüft werden |
| `-KerberosScope` | `DiscoveredOnly` | Wie breit die EncType-Abfrage im AD läuft |
| `-SkipRemoteCheck` | aus | Nur Phase 1 + 1.5, kein WinRM |
| `-ExportCsv` | `C:\Temp\SMB_Kerberos_report_[ts].csv` | Export-Pfad |

### Beispiele

```powershell
# Standard: alle Server, DiscoveredOnly Kerberos
.\Check-Server2025Defaults-v4.ps1

# Nur DCs prüfen
.\Check-Server2025Defaults-v4.ps1 -Scope DomainControllers

# Nur AD-Discovery, kein WinRM
.\Check-Server2025Defaults-v4.ps1 -SkipRemoteCheck

# Alle Accounts in der Domäne (>5000 Objekte)
.\Check-Server2025Defaults-v4.ps1 -KerberosScope Full
```

### Erzeugte Dateien

| Datei | Inhalt |
|---|---|
| `SMB_Kerberos_report_[ts].csv` | Hauptreport: SMB, LDAP, NTLM, Kerberos pro Server |
| `..._KerberosAudit.csv` | msDS-SupportedEncryptionTypes pro Account |
| `..._recommendations.csv` | Mehrheitsbasierte Empfehlungen |
| `..._urgent_fix.csv` | CRITICAL/HIGH Items mit PowerShell-Fix-Befehl |

### KerberosScope Erklärung

| Scope | Objekte | LDAP-Last | Wann verwenden |
|---|---|---|---|
| `DiscoveredOnly` | ~100-200 | Gering | Standard, SOC-freundlich |
| `AllServers` | ~300-500 | Mittel | Alle Server-Accounts |
| `Full` | ~5000+ | Hoch | Gesamte Domäne inkl. Workstations |

---

## Prove-RC4Usage.ps1

Beweist ob und welche RC4-Tickets aktuell fließen. Acht Event-Log-Checks.

### Syntax

```powershell
.\Prove-RC4Usage.ps1
    [-Hours <int>]
    [-MaxEvents <int>]
    [-ExportPath <Pfad>]
    [-CountOnly]
```

### Parameter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `-Hours` | `24` | Zeitraum in Stunden |
| `-MaxEvents` | `500` | Max Events pro Abfrage |
| `-ExportPath` | `C:\Temp` | Zielordner für CSVs |
| `-CountOnly` | aus | Nur Zählung per wevtutil, kein Parsing |

### Beispiele

```powershell
# Standard: letzte 24h
.\Prove-RC4Usage.ps1

# Letzte 72h, höheres Limit
.\Prove-RC4Usage.ps1 -Hours 72 -MaxEvents 5000

# Schnelle Zählung ohne CSV-Export
.\Prove-RC4Usage.ps1 -CountOnly
```

### Die 8 Checks

| Nr | Event | Was es prüft |
|---|---|---|
| 1 | 4768 | TGT Encryption Type Verteilung |
| 2 | 4769 | RC4 Service Tickets (server-side FilterXML) |
| 3 | 14, 4 | KDC EncType Errors |
| 4 | 4770 | RC4 Ticket Renewals |
| 5 | 4771 | Kerberos Pre-Auth Failed |
| 6 | 4625 + 4740 | NTLM Failed Logon + Lockout (60s Korrelation) |
| 7 | 2887/2889/3039 | LDAP Signing + Channel Binding |
| 8 | AD | msDS-SupportedEncryptionTypes pro Account |

### Erzeugte CSVs

Alle in `C:\Temp\` (oder `-ExportPath`), Semikolon-Delimiter:

`RC4_Proof_TGT_*.csv`, `RC4_Proof_SvcTickets_*.csv`, `RC4_Proof_Renewals_*.csv`,
`RC4_Proof_PreAuth_*.csv`, `RC4_Proof_LogonFails_*.csv`, `RC4_Proof_Lockouts_*.csv`,
`RC4_Proof_Korrelation_*.csv`, `RC4_Proof_UnsignedLDAP_*.csv`, `RC4_Proof_URGENT_*.csv`

---

## Discover-RC4Environment.ps1

Erkennt RC4-anfällige Systeme in heterogenen Umgebungen und korreliert Events.

### Syntax

```powershell
.\Discover-RC4Environment.ps1
    [-Hours <int>]
    [-MaxEvents <int>]
    [-ReportPath <Pfad>]
    [-ReassessFrom <Pfad>]
    [-SkipEvents]
    [-ImportOnly]
    [-SendMail]
    [-MailTo <string>]
    [-MailFrom <string>]
    [-SmtpServer <string>]
```

### Parameter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `-Hours` | `24` | Event-Log Zeitraum |
| `-MaxEvents` | `1000` | Max Events pro Abfrage |
| `-ReportPath` | `C:\Temp` | Zielordner |
| `-ReassessFrom` | — | Pfad zu vorherigem Report → nur Kreuzprüfung, kein Scan |
| `-SkipEvents` | aus | Nur AD-Discovery, keine Event-Logs |
| `-ImportOnly` | aus | Funktionen laden, kein Scan (für Dot-Sourcing) |
| `-SendMail` | aus | ZIP per E-Mail versenden |
| `-MailTo` | — | Empfänger |
| `-SmtpServer` | — | SMTP-Server |

### Drei Betriebsmodi

#### Modus 1: Vollständiger Scan (auf dem DC)

```powershell
.\Discover-RC4Environment.ps1 -Hours 24
```

Führt AD-Discovery + Event-Korrelation + Kreuzprüfung + Export durch.

#### Modus 2: Reassessment (auf Workstation, ohne DC)

```powershell
.\Discover-RC4Environment.ps1 -ReassessFrom 'C:\Temp\RC4_CONTOSO_20260319_162051'
```

Lädt CSVs aus einem vorherigen Scan und führt nur die Kreuzprüfung durch. Keine AD-Abfragen, kein WinRM, kein EventLog.

#### Modus 3: Funktionsbibliothek (Dot-Sourcing)

```powershell
. .\Discover-RC4Environment.ps1 -ImportOnly

# Einzelne Funktionen verwenden:
$citrix = Get-CitrixInfrastructure
$deleg  = Get-DelegationAccounts
$gpo    = Get-KerberosGPOPolicy
$prev   = Import-PreviousReport -Path 'C:\Temp\RC4_CONTOSO_...'
```

#### Verfügbare Funktionen (bei Dot-Sourcing)

| Funktion | Beschreibung |
|---|---|
| `Get-CitrixInfrastructure` | StoreFront, DDC, VDA, NetScaler, Service Accounts |
| `Get-IgelDevices` | Igel/Thin Client Erkennung |
| `Get-NonWindowsDevices` | Linux, macOS, VMware, Appliances |
| `Get-DelegationAccounts` | Constrained + Unconstrained Delegation |
| `Get-KerberosGPOPolicy` | GPO-Wert mit Empfehlung |
| `Get-RC4TicketsBySystem` | Event-Korrelation mit System-Matching |
| `Write-Kreuzpruefung` | Bedingte Risikobewertung aus kombinierten Befunden |
| `Import-PreviousReport` | CSV-Import für Reassessment |
| `Export-ExcelReport` | Excel mit Highlighting (ImportExcel) |
| `Get-Bewertung` | Deutsche Klartext-Bewertung pro Fund |
| `Get-DelegationBewertung` | Delegation-spezifische Bewertung |
| `Get-EncCategory` | Bitmask → Kategorie (RC4_ONLY, AES_ONLY, etc.) |
| `SafeCount` | StrictMode-sicherer Count für Arrays/Einzelobjekte |

### Kreuzprüfung (8 Checks)

| Nr | Check | Typ-Möglichkeiten |
|---|---|---|
| 1 | RC4 in Accounts vs. RC4 Tickets | PASSIV / AKTIV / OK |
| 2 | GPO vs. Account-Realität | SCHLAFEND / ÜBERGANG / OK |
| 3 | Delegation + RC4 vs. Tickets | SCHLAFEND / AKTIV |
| 4 | PreAuth vs. RC4 | GETRENNT / AKTIV |
| 5 | SMB Signing (Verweis) | HINWEIS |
| 6 | SAP Indikation | IMPLIZIT MITIGIERT / PRÜFEN |
| 7 | Maschinenkonto-Rotation | SCHLAFEND |
| 8 | NOT SET Accounts vs. April 2026 | SCHLAFEND |

#### Typ-Bedeutungen

| Typ | Bedeutung |
|---|---|
| **AKTIV** | Jetzt ein Problem. Sofort handeln. |
| **SCHLAFEND** | Kein Problem heute, aber ein konkreter Trigger aktiviert es. |
| **PASSIV** | Formell vorhanden, faktisch mitigiert. Aufräumen risikofrei. |
| **IMPLIZIT MITIGIERT** | Durch andere Befunde ausgeschlossen (z.B. SAP bei 0 RC4-Tickets). |
| **GETRENNT** | Befund existiert aber hat eine andere Ursache als RC4. |

### Erzeugte Dateien

Ordner: `C:\Temp\RC4_[domain]_[timestamp]\`

| Datei | Inhalt |
|---|---|
| `Citrix.csv` | Citrix-Systeme mit EncType, Bewertung, FixCmd |
| `Igel.csv` | Igel Thin Clients |
| `NonWindows.csv` | Linux, macOS, VMware, Appliances |
| `Delegation.csv` | KCD-Accounts mit DelegateTo |
| `GPO_Policy.csv` | Kerberos GPO mit Empfehlung |
| `PreAuthFails.csv` | Event 4771 |
| `LogonFails.csv` | Event 4625 |
| `Lockouts.csv` | Event 4740 |
| `Correlated.csv` | Lockouts korreliert mit Kerberos-Fehlern |
| `Kreuzpruefung.csv` | Bedingte Risikobewertung |
| `RC4_[domain]_Report.xlsx` | Excel mit Highlighting (benötigt ImportExcel) |

### ImportExcel installieren

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

Ohne ImportExcel: automatischer Fallback auf CSV-Export.

---

## New-RC4Report.ps1

Management-Report (XLSX + HTML) aus vorhandenen CSVs. Kein AD, kein WinRM.

### Syntax

```powershell
.\New-RC4Report.ps1
    -ReportPath <Pfad>
    [-OutputPath <Pfad>]
    [-DomainLabel <string>]
```

### Parameter

| Parameter | Standard | Beschreibung |
|---|---|---|
| `-ReportPath` | *Pflicht* | Ordner mit den CSVs |
| `-OutputPath` | `ReportPath\Report_[ts]` | Zielordner |
| `-DomainLabel` | Aus Ordnername | Anzeigename der Domäne |

### Beispiele

```powershell
# Standard: Domain aus Ordnername
.\New-RC4Report.ps1 -ReportPath 'C:\Temp\RC4_CONTOSO_20260319_162051'

# Mehrere Umgebungen
$folders = @(
    'C:\Temp\RC4_CONTOSO_20260319_162051'
    'C:\Temp\RC4_BRANCH_20260319_162058'
    'C:\Temp\RC4_SCHOOL_20260319_162105'
)
foreach ($f in $folders) {
    .\New-RC4Report.ps1 -ReportPath $f
}
```

### Was der Report enthält

#### Excel-Tabs

| Tab | Inhalt |
|---|---|
| Uebersicht | Ampel-Dashboard mit Aktiv/Schlafend/Passiv |
| Findings | 9 Findings mit Befund, Betroffene, Auswirkung, Mitigation, Seiteneffekte |
| Urgent_Fixes | DCs mit DES, Trusts ohne AES — mit PowerShell-Fix |
| Citrix | Citrix-Systeme mit EncCategory und Bewertung |
| Delegation | KCD-Accounts mit DelegateTo-Zielen |
| SMB_Signing | Server/Client Required pro System |

#### HTML

Standalone HTML-Datei. Kein Server nötig, druckbar, per E-Mail versendbar.

### Die 9 Findings

| Nr | Titel | Felder |
|---|---|---|
| 1 | RC4 in Accounts | Befund, Betroffene (namentlich), Auswirkung, Mitigation (PowerShell), Seiteneffekte |
| 2 | GPO Encryption Policy | GPO-Wert, Empfehlung, Deadline |
| 3 | Trusts ohne AES | Trust-Namen, ksetup-Befehle |
| 4 | DCs mit DES | DC-Namen, Set-ADComputer Befehle, GPO-Warnung |
| 5 | Delegation mit RC4 | Account-Namen, DelegateTo, Keytab-Anleitung |
| 6 | SAP Kompatibilität | Implizit mitigiert bei 0 RC4-Tickets |
| 7 | PreAuth / Credential-Hygiene | Top Accounts, Ursachen, Abgrenzung zu RC4 |
| 8 | NOT SET Accounts | Anzahl, April-2026-Deadline |
| 9 | SMB Signing | Mismatch-Erkennung, Konsistenz-Prüfung |

#### Finding-Felder erklärt

| Feld | Was es enthält |
|---|---|
| **Befund** | Was wurde gefunden (Zahlen, Fakten) |
| **Betroffene** | Welche Systeme/Accounts (namentlich) |
| **Auswirkung** | Was passiert wenn nichts getan wird, und unter welcher Bedingung |
| **Mitigation** | Konkreter Fix (PowerShell-Befehl, GPO-Änderung) |
| **Seiteneffekte** | Was der Fix kaputt machen könnte — oder "risikofrei" mit Begründung |

---

## CSV-Format

Alle CSVs verwenden:
- **Delimiter:** Semikolon (`;`)
- **Encoding:** UTF-8 with BOM
- **Zeilenende:** CRLF

Import in PowerShell:
```powershell
Import-Csv 'C:\Temp\RC4_CONTOSO_...\Citrix.csv' -Delimiter ';'
```

Import in Excel: Datei → Öffnen → Delimiter "Semikolon" wählen.

---

## Verschlüsselungstypen-Referenz

### msDS-SupportedEncryptionTypes Werte

| Wert | Bedeutung | Kategorie | Bewertung |
|---|---|---|---|
| 0 / NULL | Nicht gesetzt | NOT_SET | Folgt Domain-Default. Ab April 2026: AES-only |
| 4 | RC4-only | RC4_ONLY | Fehler bei Server 2025 DC |
| 8 | AES128-only | AES_ONLY | OK |
| 16 | AES256-only | AES_ONLY | OK |
| 24 | AES128 + AES256 | AES_ONLY | Zielzustand |
| 28 | RC4 + AES128 + AES256 | RC4_AES | KDC kann RC4 wählen |
| 31 | DES + RC4 + AES | DES_PRESENT | Sofort ändern |
| 2147483640 | AES + Future (GPO) | AES_ONLY | Ziel-GPO |
| 2147483644 | RC4 + AES + Future (GPO) | RC4_AES | Übergangs-GPO |
| 2147483647 | Alles inkl. DES (GPO) | DES_PRESENT | Sofort ändern |

### Event-IDs

| Event | Log | Bedeutung |
|---|---|---|
| 4768 | Security | TGT angefordert (Encryption Type im Event) |
| 4769 | Security | Service Ticket angefordert |
| 4770 | Security | Ticket Renewal |
| 4771 | Security | Kerberos Pre-Auth fehlgeschlagen |
| 4625 | Security | Logon fehlgeschlagen |
| 4740 | Security | Account Lockout |
| 2887 | Directory Service | LDAP Unsigned Binds (24h Zusammenfassung) |
| 2889 | Directory Service | LDAP Unsigned Bind (einzeln) |

---

## Referenzen

- [Microsoft Learn: Detect and Remediate RC4](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Blog: Beyond RC4 (Dezember 2025)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/)
- [Microsoft Support: CVE-2026-20833](https://support.microsoft.com/de-de/topic/verwalten-der-kerberos-kdc-verwendung-von-rc4-1ebcda33-720a-4da8-93c1-b0496e1910dc)
- [MSXFAQ: Kerberos RC4 Abschaltung (Frank Carius)](https://www.msxfaq.de/windows/kerberos/kerberos_rc4_abschaltung.htm)
- [MSXFAQ: Kerberos Encryption](https://www.msxfaq.de/windows/kerberos/kerberos_encryption.htm)
- [DSInternals: SMB Signing Defaults](https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/)
- [Borns IT-Blog: Server 2025 DC — Finger weg](https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/)
- [Frankys Web: Server 2025 DC Inplace Upgrade](https://www.frankysweb.de/en/windows-server-2025-domain-controller-inplace-upgrade/)
