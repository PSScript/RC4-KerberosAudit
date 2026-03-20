#Requires -Version 5.1
<#
.SYNOPSIS
    Erzeugt einen Management-Report (XLSX + HTML) aus den CSVs von
    Check-Server2025Defaults und Discover-RC4Environment.

.DESCRIPTION
    Liest alle verfuegbaren CSVs aus einem Report-Ordner und erzeugt:
    - Excel mit Uebersicht, Findings, betroffene Systeme, Mitigations
    - HTML-Report fuer Browser/E-Mail (standalone, kein Server noetig)

    Keine AD-Abfragen, kein WinRM, kein EventLog.
    Laeuft auf jedem Windows-System mit PowerShell 5.1.

.PARAMETER ReportPath
    Pfad zum Ordner mit den CSVs (z.B. C:\Temp\RC4_CONTOSO_20260319_162051)

.PARAMETER OutputPath
    Zielordner fuer den Report. Standard: ReportPath\Report_[timestamp]

.PARAMETER DomainLabel
    Anzeigename der Domaene. Wird aus dem Ordnernamen erkannt wenn nicht angegeben.

.EXAMPLE
    .\New-RC4Report.ps1 -ReportPath 'C:\Temp\RC4_CONTOSO_20260319_162051'
    .\New-RC4Report.ps1 -ReportPath 'C:\Temp\RC4_DGBRS_20260319_162058' -DomainLabel 'DGBRS'

.NOTES
    Version : 1.0
    Requires: ImportExcel (optional — HTML wird immer erzeugt)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReportPath,
    [string]$OutputPath,
    [string]$DomainLabel
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'

#region ============ HELPERS ============

function SafeCount { param($C) if ($null -eq $C) {0} elseif ($C -is [array]) {$C.Length} else {1} }

function Import-OptionalCsv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @() }
    try { @(Import-Csv $Path -Delimiter ';' -Encoding UTF8) } catch { @() }
}

function Get-EncCategoryFromValue {
    param($Value)
    if ($null -eq $Value -or $Value -eq '' -or $Value -eq '0') { return 'NOT_SET' }
    $v = [int]$Value
    if ($v -band 0x3) { return 'DES_PRESENT' }
    if (($v -band 0x4) -and -not (($v -band 0x8) -or ($v -band 0x10))) { return 'RC4_ONLY' }
    if (($v -band 0x4) -and (($v -band 0x8) -or ($v -band 0x10))) { return 'RC4_AES' }
    if (($v -band 0x8) -or ($v -band 0x10)) { return 'AES_ONLY' }
    return 'UNKNOWN'
}

#endregion

#region ============ DATA LOADING ============

Write-Host "`n=== RC4 Report Generator ===" -ForegroundColor Cyan
Write-Host "  Quelle: $ReportPath"

if (-not (Test-Path $ReportPath)) {
    Write-Host "  FEHLER: Pfad nicht gefunden." -ForegroundColor Red; return
}

# Detect domain from folder name
if (-not $DomainLabel) {
    $folder = Split-Path $ReportPath -Leaf
    if ($folder -match 'RC4_([^_]+)_') { $DomainLabel = $Matches[1] } else { $DomainLabel = 'UNKNOWN' }
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $ReportPath "Report_$ts"
}
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }

# Load CSVs — try multiple naming patterns
$citrix    = Import-OptionalCsv (Join-Path $ReportPath 'Citrix.csv')
$igel      = Import-OptionalCsv (Join-Path $ReportPath 'Igel.csv')
$nonwin    = Import-OptionalCsv (Join-Path $ReportPath 'NonWindows.csv')
$deleg     = Import-OptionalCsv (Join-Path $ReportPath 'Delegation.csv')
$gpoCsv    = Import-OptionalCsv (Join-Path $ReportPath 'GPO_Policy.csv')
$lockouts  = Import-OptionalCsv (Join-Path $ReportPath 'Lockouts.csv')
$preAuth   = Import-OptionalCsv (Join-Path $ReportPath 'PreAuthFails.csv')
$logonFail = Import-OptionalCsv (Join-Path $ReportPath 'LogonFails.csv')
$correl    = Import-OptionalCsv (Join-Path $ReportPath 'Correlated.csv')

# RC4 Tickets — try both names
$rc4Tickets = Import-OptionalCsv (Join-Path $ReportPath 'RC4Tickets.csv')
if ((SafeCount $rc4Tickets) -eq 0) {
    $rc4Tickets = Import-OptionalCsv (Join-Path $ReportPath 'RC4_Tickets.csv')
}

# SMB/Kerberos from Check-Server2025Defaults (find by pattern)
$smbCsv = @()
$kerbAudit = @()
$urgentFix = @()
$recommendations = @()
$smbFiles = @(Get-ChildItem $ReportPath -Filter 'SMB_Kerberos_report_*.csv' -EA SilentlyContinue | Where-Object { $_.Name -notmatch 'Kerberos|recommendation|urgent' })
$kerbFiles = @(Get-ChildItem $ReportPath -Filter '*_KerberosAudit.csv' -EA SilentlyContinue)
$urgFiles = @(Get-ChildItem $ReportPath -Filter '*_urgent_fix.csv' -EA SilentlyContinue)
$recFiles = @(Get-ChildItem $ReportPath -Filter '*_recommendations.csv' -EA SilentlyContinue)
# Also check Audit_DG pattern
$smbFiles += @(Get-ChildItem $ReportPath -Filter 'Audit_*.csv' -EA SilentlyContinue | Where-Object { $_.Name -notmatch 'Kerberos|recommendation|urgent' })

if ($smbFiles.Count -gt 0) { $smbCsv = Import-OptionalCsv $smbFiles[0].FullName }
if ($kerbFiles.Count -gt 0) { $kerbAudit = Import-OptionalCsv $kerbFiles[0].FullName }
if ($urgFiles.Count -gt 0) { $urgentFix = Import-OptionalCsv $urgFiles[0].FullName }
if ($recFiles.Count -gt 0) { $recommendations = Import-OptionalCsv $recFiles[0].FullName }

# PreAuth Detail (drill-down)
$preAuthDetail = @()
$padFiles = @(Get-ChildItem $ReportPath -Filter 'PreAuth_Detail_*.csv' -EA SilentlyContinue)
if ($padFiles.Count -gt 0) { $preAuthDetail = Import-OptionalCsv $padFiles[0].FullName }

# DC Self-Failed Logons
$selfFails = @()
$sfFiles = @(Get-ChildItem $ReportPath -Filter 'DC_SelfFailedLogons_*.csv' -EA SilentlyContinue)
if ($sfFiles.Count -gt 0) { $selfFails = Import-OptionalCsv $sfFiles[0].FullName }

# KDCSVC Audit Events (seit Januar 2026 CU)
$kdcsvcEvents = @()
$kdcFiles = @(Get-ChildItem $ReportPath -Filter 'KDCSVC_Audit.csv' -EA SilentlyContinue)
if ($kdcFiles.Count -gt 0) { $kdcsvcEvents = Import-OptionalCsv $kdcFiles[0].FullName }

# NTLMv1 Usage
$ntlmV1 = @()
$ntlmFiles = @(Get-ChildItem $ReportPath -Filter 'NTLMv1_Usage.csv' -EA SilentlyContinue)
if ($ntlmFiles.Count -gt 0) { $ntlmV1 = Import-OptionalCsv $ntlmFiles[0].FullName }

# GPO reconstruction
$gpo = $null
if ((SafeCount $gpoCsv) -gt 0) {
    $row = $gpoCsv | Select-Object -First 1
    $gpoVal = if ($row.Value -and $row.Value -ne '') { try { [int]$row.Value } catch { $null } } else { $null }
    $gpo = [PSCustomObject]@{
        Value=$gpoVal; HasDES=$($row.HasDES -eq 'True'); HasRC4=$($row.HasRC4 -eq 'True')
        HasAES128=$($row.HasAES128 -eq 'True'); HasAES256=$($row.HasAES256 -eq 'True')
        Recommendation=$row.Recommendation
    }
}

Write-Host "  Domain     : $DomainLabel" -ForegroundColor White
Write-Host "  Citrix     : $(SafeCount $citrix)" -ForegroundColor DarkGray
Write-Host "  Delegation : $(SafeCount $deleg)" -ForegroundColor DarkGray
Write-Host "  SMB Servers: $(SafeCount $smbCsv)" -ForegroundColor DarkGray
Write-Host "  KerbAudit  : $(SafeCount $kerbAudit)" -ForegroundColor DarkGray
Write-Host "  Urgent Fix : $(SafeCount $urgentFix)" -ForegroundColor DarkGray
Write-Host "  RC4 Tickets: $(SafeCount $rc4Tickets)" -ForegroundColor DarkGray
Write-Host "  PreAuth    : $(SafeCount $preAuth) (Detail: $(SafeCount $preAuthDetail))" -ForegroundColor DarkGray

#endregion

#region ============ FINDINGS ENGINE ============

$allDiscovery = @() + $citrix + $igel + $nonwin
$rc4Risk = @($allDiscovery | Where-Object {
    $cat = if ($_.EncCategory) { $_.EncCategory } else { 'UNKNOWN' }
    $cat -in @('RC4_ONLY','RC4_AES','DES_PRESENT')
})

$findings = @()

# --- Finding 1: RC4 in Accounts ---
$rc4TicketCount = SafeCount $rc4Tickets
$rc4RiskCount = SafeCount $rc4Risk

$f1Impact = @($rc4Risk | Select-Object -First 10 | ForEach-Object {
    "$($_.Name) ($($_.Role), EncType=$($_.EncCategory))"
}) -join "`n"
if ($rc4RiskCount -gt 10) { $f1Impact += "`n... und $($rc4RiskCount - 10) weitere" }

$findings += [PSCustomObject]@{
    Nr=1; Typ=if($rc4TicketCount -gt 0){'AKTIV'}else{'PASSIV'}
    Titel='RC4 in Computer/Service Accounts'
    Befund="$rc4RiskCount Accounts haben RC4 oder DES im Attribut msDS-SupportedEncryptionTypes. $rc4TicketCount RC4-verschluesselte Service Tickets in den letzten 24 Stunden."
    Betroffene=$f1Impact
    Auswirkung=if($rc4TicketCount -gt 0){"Der KDC stellt aktiv RC4-Tickets aus. Server 2025 Systeme lehnen diese ab. Authentifizierung schlaegt bei ca. $rc4TicketCount Verbindungen pro Tag fehl."}else{"Aktuell kein Ausfall — der KDC waehlt AES. Das Risiko wird aktiv bei Server 2025 DC Promotion, Exchange SE Go-Live unter Last, oder dem April-2026-Update (CVE-2026-20833)."}
    Mitigation="Alle betroffenen Accounts auf Wert 24 (AES-only) setzen:`nSet-ADComputer '<Name>' -KerberosEncryptionType AES128,AES256`nDanach: Passwort rotieren damit AES-Keys generiert werden."
    Seiteneffekte=if($rc4TicketCount -eq 0){"Risikofrei — der KDC stellt bereits AES-Tickets fuer diese Accounts aus. Die Aenderung formalisiert den Ist-Zustand."}else{"Systeme die nur RC4 koennen (z.B. SAP < 7.53, Igel alte FW) verlieren Zugang. Vorher mit Prove-RC4Usage.ps1 pruefen welche SPNs RC4-Tickets erhalten."}
}

# --- Finding 2: GPO ---
$gpoStatus = if (-not $gpo -or -not $gpo.Value) {'SCHLAFEND'} elseif ($gpo.HasDES) {'SCHLAFEND'} elseif ($gpo.HasRC4) {'UEBERGANG'} else {'OK'}
$gpoVal = if ($gpo) { $gpo.Value } else { 'NOT SET' }

$findings += [PSCustomObject]@{
    Nr=2; Typ=$gpoStatus
    Titel='Kerberos GPO Encryption Policy'
    Befund="GPO-Wert: $gpoVal. $(if($gpo -and $gpo.HasDES){'DES und RC4 erlaubt.'}elseif($gpo -and $gpo.HasRC4){'RC4 erlaubt, DES nicht.'}elseif(-not $gpo -or -not $gpo.Value){'Nicht konfiguriert — folgt OS-Default.'}else{'Nur AES erlaubt.'})"
    Betroffene="Alle Kerberos-Authentifizierungen in der Domaene $DomainLabel"
    Auswirkung=if($gpo -and $gpo.HasDES){"DES ist seit 2008 kryptographisch gebrochen. Kerberoasting-Angriffe koennen DES-verschluesselte Tickets gezielt anfordern. Da aktuell 0 DES-Traffic fliesst, ist die Aenderung risikofrei."}elseif(-not $gpo -or -not $gpo.Value){"Der OS-Default erlaubt aktuell RC4+AES. Ab April 2026 (CVE-2026-20833) wird der Default auf AES-only geaendert. Accounts mit Wert 0 (NOT SET) schlagen dann fehl wenn sie RC4 benoetigen."}else{"RC4 erlaubt als Uebergangszustand waehrend der Account-Bereinigung."}
    Mitigation=if($gpo -and $gpo.HasDES){"GPO sofort auf 2147483644 aendern (DES entfernen, RC4 im Uebergang belassen). Ziel: 2147483640 (AES-only) nach vollstaendiger Account-Bereinigung."}elseif(-not $gpo -or -not $gpo.Value){"GPO explizit auf 2147483644 setzen (RC4+AES, kein DES). Vor April 2026 auf 2147483640 (AES-only)."}else{"GPO auf 2147483640 (AES-only) erst setzen wenn alle Accounts auf Wert 24 und Passwoerter rotiert."}
    Seiteneffekte=if($gpo -and $gpo.HasDES -and $rc4TicketCount -eq 0){"Risikofrei — 0 DES/RC4-Traffic. Die Aenderung entfernt nur eine theoretische Angriffsflaeche."}elseif(-not $gpo -or -not $gpo.Value){"Keine Seiteneffekte beim Setzen auf 2147483644. Seiteneffekte bei 2147483640: alle Accounts mit RC4-Abhaengigkeit verlieren Zugang."}else{"Keine bei aktuellem Wert."}
}

# --- Finding 3: Trusts ---
$trustsUrgent = @($urgentFix | Where-Object { $_.Roles -eq 'Trust' -or $_.Issue -match 'Trust' })
if ((SafeCount $trustsUrgent) -gt 0) {
    $trustNames = ($trustsUrgent | ForEach-Object { $_.ComputerName }) -join ', '
    $trustFix = ($trustsUrgent | ForEach-Object { $_.Fix }) -join "`n"
    $findings += [PSCustomObject]@{
        Nr=3; Typ='SCHLAFEND'
        Titel='Trust-Objekte ohne AES'
        Befund="$(SafeCount $trustsUrgent) Trust(s) ohne AES im Attribut: $trustNames. Cross-Domain-Authentifizierung verwendet RC4."
        Betroffene=$trustNames
        Auswirkung="Benutzer und Dienste die ueber diese Trusts authentifizieren erhalten RC4-Tickets. Bei Server 2025 DC oder nach April-2026-Update schlaegt Cross-Domain-Auth fehl."
        Mitigation=$trustFix
        Seiteneffekte="Der ksetup-Befehl fuegt AES zu den unterstuetzten Typen hinzu und belaesst RC4 als Fallback. Kein Risiko fuer bestehende Verbindungen."
    }
}

# --- Finding 4: DCs mit DES ---
$dcsDES = @($urgentFix | Where-Object { $_.Issue -match 'DES enabled' })
if ((SafeCount $dcsDES) -gt 0) {
    $dcNames = ($dcsDES | ForEach-Object { $_.ComputerName }) -join ', '
    $dcFix = ($dcsDES | Select-Object -First 1).Fix
    $findings += [PSCustomObject]@{
        Nr=4; Typ='SCHLAFEND'
        Titel='Domain Controller mit DES im Attribut'
        Befund="$(SafeCount $dcsDES) DCs haben Wert 31 (DES+RC4+AES): $dcNames"
        Betroffene=$dcNames
        Auswirkung="Der KDC kann theoretisch DES-Tickets fuer diese DCs ausstellen. Bei Kerberoasting-Angriffen sind DES-verschluesselte Tickets leichter zu knacken als RC4 oder AES."
        Mitigation="Alle betroffenen DCs auf AES-only setzen:`n$dcFix`nWICHTIG: Wenn eine GPO den Wert 31 erzwingt, muss die GPO ebenfalls geaendert werden — sonst setzt gpupdate den Wert zurueck."
        Seiteneffekte="Risikofrei wenn die GPO ebenfalls angepasst wird. Der KDC stellt bereits AES-Tickets aus (0 DES/RC4-Traffic). Die Aenderung entfernt nur die DES/RC4-Faehigkeit aus dem Account."
    }
}

# --- Finding 5: Delegation ---
$delegRC4 = @($deleg | Where-Object {
    $cat = if ($_.EncCategory) { $_.EncCategory } else { 'UNKNOWN' }
    $cat -in @('RC4_ONLY','RC4_AES','DES_PRESENT')
})
if ((SafeCount $delegRC4) -gt 0) {
    $delegNames = ($delegRC4 | ForEach-Object { "$($_.Name) ($($_.DelegationType) -> $($_.DelegateTo.Substring(0, [Math]::Min(50, $_.DelegateTo.Length))))" }) -join "`n"
    $findings += [PSCustomObject]@{
        Nr=5; Typ=if($rc4TicketCount -gt 0){'AKTIV'}else{'SCHLAFEND'}
        Titel='Delegation-Accounts mit RC4/DES'
        Befund="$(SafeCount $delegRC4) Constrained Delegation Accounts mit RC4 oder DES im Attribut."
        Betroffene=$delegNames
        Auswirkung="Constrained Delegation (S4U2Proxy) verwendet eine andere Encryption-Aushandlung. Der Encryption Type des delegierten Tickets haengt vom Proxy-Account ab, nicht vom Benutzer. Unter hoher Last kann der KDC RC4 fuer das delegierte Ticket waehlen — besonders kritisch bei Exchange SE Go-Live."
        Mitigation="Accounts auf Wert 24 setzen + Keytabs mit AES neu erstellen:`nSet-ADComputer '<Name>' -KerberosEncryptionType AES128,AES256`nktpass /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL ..."
        Seiteneffekte=if($rc4TicketCount -eq 0){"Risikofrei bei 0 RC4-Traffic. Die Delegation verwendet bereits AES."}else{"Keytab muss vor der Account-Aenderung mit AES neu erstellt werden. Reihenfolge: 1. Neues Keytab, 2. Account aendern, 3. Keytab auf LoadBalancer deployen."}
    }
}

# --- Finding 6: SAP ---
$findings += [PSCustomObject]@{
    Nr=6; Typ=if($rc4TicketCount -eq 0){'HINWEIS'}else{'PRUEFEN'}
    Titel='SAP Kerberos-Kompatibilitaet'
    Befund=if($rc4TicketCount -eq 0){"0 RC4-Tickets — SAP erhaelt und akzeptiert AES-Tickets."}else{"$rc4TicketCount RC4-Tickets — pruefen ob SAP-SPNs betroffen sind."}
    Betroffene='SAP Application Server'
    Auswirkung=if($rc4TicketCount -eq 0){"Hinweis. Wenn SAP heute mit AES funktioniert, funktioniert es auch nach DC-Umstellung auf Wert 24, Server 2025 DC, und April-2026-Update."}else{"Wenn SAP < 7.53 und RC4-Tickets fuer SAP-SPNs fliessen: SAP Kernel Update auf >= 7.53 erforderlich."}
    Mitigation=if($rc4TicketCount -eq 0){"Keine Aktion noetig."}else{"RC4-Tickets nach SAP-SPNs filtern. Wenn betroffen: SAP Kernel Update."}
    Seiteneffekte='Keine — SAP verwendet bereits AES.'
}

# --- Finding 7: PreAuth / Credential Hygiene ---
$preAuthCount = SafeCount $preAuth
if ($preAuthCount -gt 50) {
    $topAccounts = ''
    if ((SafeCount $preAuthDetail) -gt 0) {
        $topAccounts = @($preAuthDetail | Where-Object { $_.Status -eq '0x18' } | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count)x)" }) -join ', '
    }
    $findings += [PSCustomObject]@{
        Nr=7; Typ='GETRENNT'
        Titel='Pre-Authentication Fehler (Credential-Hygiene)'
        Befund="$preAuthCount Pre-Auth Fehler (Event 4771) in 24 Stunden. 0 RC4-Tickets, $(SafeCount $correl) korrelierte Lockouts."
        Betroffene=if($topAccounts){"Top Accounts: $topAccounts"}else{"Details in PreAuthFails.csv"}
        Auswirkung="Getrennt vom RC4-Thema. Die Fehler entstehen durch falsche Passwoerter (gespeicherte alte Credentials in Diensten, Outlook-Profilen, Mobilgeraeten). Wird RC4-relevant nach dem April-2026-Update wenn die Fallback-Kette (Kerberos->NTLM) haeufiger getriggert wird."
        Mitigation="Betroffene Accounts identifizieren (PreAuth_Detail CSV). Haeufigste Ursachen: Outlook-Profile mit altem PW, ActiveSync-Geraete, Scheduled Tasks mit persoenlichen Credentials, SharePoint AD Sync."
        Seiteneffekte='Keine — Credential-Bereinigung hat keine negativen Seiteneffekte.'
    }
}

# --- Finding 8: NOT SET Accounts ---
$notSet = @($allDiscovery | Where-Object { $_.EncCategory -eq 'NOT_SET' })
if ((SafeCount $notSet) -gt 0) {
    $findings += [PSCustomObject]@{
        Nr=8; Typ='SCHLAFEND'
        Titel='Accounts ohne expliziten Verschluesselungstyp (Wert 0)'
        Befund="$(SafeCount $notSet) Accounts mit msDS-SupportedEncryptionTypes = 0 (NOT SET)."
        Betroffene=(@($notSet | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Role))" }) -join ', ') + $(if ((SafeCount $notSet) -gt 10) { " ... +$((SafeCount $notSet) - 10) weitere" })
        Auswirkung="Diese Accounts folgen dem Domain-Default. Ab April 2026 (CVE-2026-20833) wird der Default auf AES-only geaendert. Wenn diese Accounts Dienste bedienen die RC4 benoetigen, schlaegt die Authentifizierung fehl."
        Mitigation="Explizit auf Wert 24 (AES-only) oder 28 (RC4+AES) setzen, je nach System-Faehigkeit. Deadline: vor dem April-2026-Patchday."
        Seiteneffekte='Beim Setzen auf 24 (AES-only): Systeme die nur RC4 koennen verlieren Zugang. Beim Setzen auf 28 (RC4+AES): keine Seiteneffekte, RC4 bleibt als Fallback.'
    }
}

# --- Finding 9: SMB Signing ---
if ((SafeCount $smbCsv) -gt 0) {
    # Detect column names
    $colNames = ($smbCsv | Select-Object -First 1).PSObject.Properties.Name
    $srvCol = $colNames | Where-Object { $_ -match 'SMBServer|ServerRequire|Server_Require' } | Select-Object -First 1
    $cliCol = $colNames | Where-Object { $_ -match 'SMBClient|ClientRequire|Client_Require' } | Select-Object -First 1

    if ($srvCol -and $cliCol) {
        $smbMismatch = @($smbCsv | Where-Object { $_.$srvCol -ne $_.$cliCol })
        $allTrue = @($smbCsv | Where-Object { $_.$srvCol -eq 'True' -and $_.$cliCol -eq 'True' })

        $findings += [PSCustomObject]@{
            Nr=9; Typ=if((SafeCount $smbMismatch) -gt 0){'WARNUNG'}elseif((SafeCount $allTrue) -eq (SafeCount $smbCsv)){'OK'}else{'HINWEIS'}
            Titel='SMB Signing Konsistenz'
            Befund="$(SafeCount $smbCsv) Server geprueft. $(SafeCount $allTrue) mit Server+Client Required=True. $(SafeCount $smbMismatch) mit Mismatch."
            Betroffene=if((SafeCount $smbMismatch) -gt 0){($smbMismatch | Select-Object -First 5 | ForEach-Object { $n = if ($_.Name) {$_.Name} elseif ($_.ComputerName) {$_.ComputerName} else {'?'}; "$n (S=$($_.$srvCol) C=$($_.$cliCol))" }) -join ', '}else{"Alle konsistent True/True — Zielzustand fuer Server 2025."}
            Auswirkung=if((SafeCount $smbMismatch) -gt 0){"Inkonsistente Signing-Einstellungen fuehren zu gelegentlichen Verbindungsabbruechen. Server 2025 erzwingt Signing — Systeme ohne Signing-Support werden abgelehnt."}else{"Kein Risiko. Alle Server verwenden konsistent SMB Signing. Server 2025 Einfuehrung ist kompatibel."}
            Mitigation=if((SafeCount $smbMismatch) -gt 0){"GPO fuer Server und Client Signing auf Required setzen. Drucker und Appliances ohne Signing-Support identifizieren und per Fine-Grained Policy ausschliessen."}else{"Keine Aktion noetig."}
            Seiteneffekte=if((SafeCount $smbMismatch) -gt 0){"Drucker/Appliances ohne SMB Signing verlieren Zugriff auf Shares (Scan-to-Share, Secure Print)."}else{"Keine."}
        }
    }
}

# --- Finding 10: KDCSVC Audit Events ---
if ((SafeCount $kdcsvcEvents) -gt 0) {
    $findings += [PSCustomObject]@{
        Nr=10; Typ='AKTIV'
        Titel='KDCSVC Audit Events (Januar 2026 CU)'
        Befund="$(SafeCount $kdcsvcEvents) KDCSVC Events im System Log. Diese zeigen praezise welche Accounts und Dienste im April 2026 fehlschlagen."
        Betroffene=(@($kdcsvcEvents | Group-Object EventID | Sort-Object Name | ForEach-Object { "Event $($_.Name): $($_.Count)x" }) -join ', ')
        Auswirkung="Die betroffenen Accounts werden ab dem April-2026-Patchday bei der Authentifizierung abgelehnt. Event 201/202/206/207 = Warnung (Audit). Event 203/204/209 = blockiert (Enforcement)."
        Mitigation="Betroffene Accounts auf AES-only (Wert 24) setzen und Passwort rotieren. Details in KDCSVC_Audit.csv."
        Seiteneffekte="Risikofrei wenn die betroffenen Accounts aktuell AES-Tickets erhalten (aus Prove-RC4Usage ersichtlich)."
    }
}

# --- Finding 11: NTLMv1 ---
if ((SafeCount $ntlmV1) -gt 0) {
    $v1Top = ($ntlmV1 | Sort-Object { [int]$_.Count } -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Account) ($($_.Count)x von $($_.Workstation))" }) -join '; '
    $findings += [PSCustomObject]@{
        Nr=11; Typ='AKTIV'
        Titel='NTLMv1 Anmeldungen — kryptographisch gebrochen'
        Befund="$(($ntlmV1 | Measure-Object -Property Count -Sum).Sum) NTLMv1-Anmeldungen erkannt. NTLMv1 ist durch Mandiant Rainbow Tables sofort kompromittierbar."
        Betroffene=$v1Top
        Auswirkung="Jede NTLMv1-Anmeldung kann durch einen Angreifer im Netzwerk abgefangen und das Passwort sofort wiederhergestellt werden. NTLMv1 ist ein groesseres Sicherheitsrisiko als RC4 in Kerberos."
        Mitigation="GPO: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM and NTLM. Betroffene Systeme (alte Firmware, alte Applikationen) identifizieren und auf NTLMv2 oder Kerberos umstellen."
        Seiteneffekte="Systeme die nur NTLMv1 koennen verlieren Zugang. Betrifft typischerweise sehr alte Appliances, Drucker oder Legacy-Software."
    }
}

# --- Priority sort: AKTIV first, then SCHLAFEND, then rest ---
$typPrio = @{ 'AKTIV'=1; 'SCHLAFEND'=2; 'WARNUNG'=2; 'UEBERGANG'=3; 'GETRENNT'=4; 'PASSIV'=5; 'HINWEIS'=5; 'HINWEIS'=5; 'HINWEIS'=6; 'OK'=7; 'PRUEFEN'=2 }
$findings = @($findings | Sort-Object { if ($typPrio[$_.Typ]) { $typPrio[$_.Typ] } else { 99 } }, Nr)

Write-Host "`n  $((SafeCount $findings)) Findings generiert (Prioritaet: AKTIV zuerst)" -ForegroundColor Cyan

#endregion

#region ============ HTML REPORT ============

$htmlFile = Join-Path $OutputPath "RC4_${DomainLabel}_Report.html"

$css = @'
body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; color: #333; background: #fafafa; }
h1 { color: #C8102E; border-bottom: 3px solid #C8102E; padding-bottom: 8px; }
h2 { color: #8B0000; margin-top: 32px; }
h3 { color: #555; margin-top: 24px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 14px; }
th { background: #C8102E; color: white; padding: 8px 10px; text-align: left; font-weight: 600; }
td { padding: 6px 10px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
tr:nth-child(even) { background: #f5f0f0; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }
.aktiv { background: #FCEBEB; color: #791F1F; }
.schlafend { background: #FFF8E1; color: #633806; }
.passiv, .hinweis, .uebergang { background: #E1F5EE; color: #085041; }
.getrennt { background: #E6F1FB; color: #0C447C; }
.ok { background: #E1F5EE; color: #085041; }
.warnung { background: #FFF8E1; color: #633806; }
.hinweis { background: #F5F5F5; color: #666; }
.finding { background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px 20px; margin: 16px 0; }
.finding h3 { margin-top: 0; }
.meta { font-size: 13px; color: #666; }
.field-label { font-weight: 600; color: #8B0000; display: block; margin-top: 10px; font-size: 13px; }
.field-value { margin: 2px 0 8px; white-space: pre-wrap; font-size: 14px; line-height: 1.5; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
.summary-card { background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 14px; }
.summary-card .label { font-size: 12px; color: #888; }
.summary-card .value { font-size: 22px; font-weight: 600; color: #333; }
.ref { font-size: 13px; color: #666; }
.ref a { color: #C8102E; }
@media print { .finding { break-inside: avoid; } body { background: white; } }
'@

$typClass = @{
    'AKTIV'='aktiv'; 'SCHLAFEND'='schlafend'; 'PASSIV'='passiv'
    'HINWEIS'='mitigiert'; 'GETRENNT'='getrennt'; 'OK'='ok'
    'UEBERGANG'='uebergang'; 'WARNUNG'='warnung'; 'HINWEIS'='hinweis'; 'PRUEFEN'='warnung'
}

$aktivCount = @($findings | Where-Object { $_.Typ -eq 'AKTIV' }).Count
$schlafCount = @($findings | Where-Object { $_.Typ -eq 'SCHLAFEND' }).Count
$passivCount = @($findings | Where-Object { $_.Typ -match 'PASSIV|MITIGIERT|GETRENNT|UEBERGANG|OK' }).Count

$htmlBody = @"
<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>RC4 Risikobewertung — $DomainLabel</title>
<style>$css</style></head><body>
<h1>Risikobewertung Kerberos RC4 — $DomainLabel</h1>
<p class="meta">Erstellt: $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Quelle: $ReportPath</p>

<div class="summary-grid">
<div class="summary-card"><div class="label">Aktive Risiken</div><div class="value" style="color:$(if($aktivCount -gt 0){'#791F1F'}else{'#085041'})">$aktivCount</div></div>
<div class="summary-card"><div class="label">Schlafend</div><div class="value" style="color:$(if($schlafCount -gt 0){'#633806'}else{'#085041'})">$schlafCount</div></div>
<div class="summary-card"><div class="label">Passiv / Mitigiert</div><div class="value" style="color:#085041">$passivCount</div></div>
<div class="summary-card"><div class="label">Systeme mit RC4/DES</div><div class="value">$rc4RiskCount</div></div>
<div class="summary-card"><div class="label">RC4 Tickets (24h)</div><div class="value" style="color:$(if($rc4TicketCount -gt 0){'#791F1F'}else{'#085041'})">$rc4TicketCount</div></div>
<div class="summary-card"><div class="label">GPO</div><div class="value" style="font-size:14px">$gpoVal</div></div>
</div>

<h2>Findings (Priorit&auml;t: kritisch zuerst)</h2>
"@

# Priority header
$aktivFindings = @($findings | Where-Object { $_.Typ -eq 'AKTIV' })
if ($aktivFindings.Count -gt 0) {
    $htmlBody += '<div style="background:#FCEBEB;border-left:4px solid #C8102E;padding:12px 16px;margin:12px 0;border-radius:0 6px 6px 0;"><strong style="color:#791F1F;">Sofort handeln:</strong> '
    $htmlBody += ($aktivFindings | ForEach-Object { "#$($_.Nr) $($_.Titel)" }) -join ' | '
    $htmlBody += '</div>'
}
$schlafFindings = @($findings | Where-Object { $_.Typ -eq 'SCHLAFEND' -or $_.Typ -eq 'WARNUNG' })
if ($schlafFindings.Count -gt 0) {
    $htmlBody += '<div style="background:#FFF8E1;border-left:4px solid #EF9F27;padding:12px 16px;margin:12px 0;border-radius:0 6px 6px 0;"><strong style="color:#633806;">Vor April 2026:</strong> '
    $htmlBody += ($schlafFindings | ForEach-Object { "#$($_.Nr) $($_.Titel)" }) -join ' | '
    $htmlBody += '</div>'
}

foreach ($f in $findings) {
    $cls = if ($typClass[$f.Typ]) { $typClass[$f.Typ] } else { 'hinweis' }
    $htmlBody += @"
<div class="finding">
<h3><span class="pill $cls">$($f.Typ)</span> #$($f.Nr): $($f.Titel)</h3>
<span class="field-label">Befund</span><div class="field-value">$($f.Befund)</div>
<span class="field-label">Betroffene Systeme / Accounts</span><div class="field-value">$($f.Betroffene -replace "`n","<br>")</div>
<span class="field-label">Auswirkung</span><div class="field-value">$($f.Auswirkung)</div>
<span class="field-label">Mitigation</span><div class="field-value">$($f.Mitigation -replace "`n","<br>")</div>
<span class="field-label">Seiteneffekte der Mitigation</span><div class="field-value">$($f.Seiteneffekte)</div>
</div>

"@
}

$htmlBody += @"
<h2>Referenzen</h2>
<div class="ref">
<p><a href="https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos">Microsoft Learn: Detect and Remediate RC4 in Kerberos</a></p>
<p><a href="https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/">Microsoft Blog: Beyond RC4 for Windows Authentication</a></p>
<p><a href="https://www.msxfaq.de/windows/kerberos/kerberos_rc4_abschaltung.htm">MSXFAQ: Kerberos RC4 Abschaltung (Frank Carius)</a></p>
<p><a href="https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/">Borns IT-Blog: Server 2025 DC — Finger weg</a></p>
<p><a href="https://support.microsoft.com/de-de/topic/verwalten-der-kerberos-kdc-verwendung-von-rc4-1ebcda33-720a-4da8-93c1-b0496e1910dc">Microsoft Support: CVE-2026-20833</a></p>
</div>
<p class="meta" style="margin-top:32px;">Generiert mit New-RC4Report.ps1 v1.0</p>
</body></html>
"@

$htmlBody | Out-File $htmlFile -Encoding UTF8
Write-Host "  HTML : $htmlFile" -ForegroundColor Green

#endregion

#region ============ EXCEL REPORT ============

$xlFile = Join-Path $OutputPath "RC4_${DomainLabel}_Report.xlsx"

$hasExcel = $false
try { Import-Module ImportExcel -EA Stop; $hasExcel = $true } catch {}

if ($hasExcel) {
    # --- Tab 1: Uebersicht ---
    $overview = @()
    $overview += [PSCustomObject]@{ Bereich='Domaene'; Wert=$DomainLabel; Status='Info' }
    $overview += [PSCustomObject]@{ Bereich='Aktive Risiken'; Wert=$aktivCount; Status=if($aktivCount -gt 0){'KRITISCH'}else{'OK'} }
    $overview += [PSCustomObject]@{ Bereich='Schlafende Risiken'; Wert=$schlafCount; Status=if($schlafCount -gt 0){'WARNUNG'}else{'OK'} }
    $overview += [PSCustomObject]@{ Bereich='Passiv/Mitigiert'; Wert=$passivCount; Status='OK' }
    $overview += [PSCustomObject]@{ Bereich='Systeme mit RC4/DES'; Wert=$rc4RiskCount; Status=if($rc4RiskCount -gt 0){'WARNUNG'}else{'OK'} }
    $overview += [PSCustomObject]@{ Bereich='RC4 Tickets (24h)'; Wert=$rc4TicketCount; Status=if($rc4TicketCount -gt 0){'KRITISCH'}else{'OK'} }
    $overview += [PSCustomObject]@{ Bereich='GPO Wert'; Wert=$gpoVal; Status=$gpoStatus }
    $overview += [PSCustomObject]@{ Bereich='Urgent Fixes'; Wert=(SafeCount $urgentFix); Status=if((SafeCount $urgentFix) -gt 0){'WARNUNG'}else{'OK'} }

    $ctStatus = @(
        (New-ConditionalText 'KRITISCH' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
        (New-ConditionalText 'WARNUNG'  -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
        (New-ConditionalText 'OK'       -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
    )

    $overview | Export-Excel -Path $xlFile -WorksheetName 'Uebersicht' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $ctStatus

    # --- Tab 2: Findings ---
    $ctFindings = @(
        (New-ConditionalText 'AKTIV'     -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
        (New-ConditionalText 'SCHLAFEND' -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
        (New-ConditionalText 'PASSIV'    -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
        (New-ConditionalText 'HINWEIS' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
        (New-ConditionalText 'GETRENNT'  -BackgroundColor '#E6F1FB' -ConditionalTextColor '#0C447C')
    )

    $findings | Select-Object Nr, Typ, Titel, Befund, Betroffene, Auswirkung, Mitigation, Seiteneffekte |
        Export-Excel -Path $xlFile -WorksheetName 'Findings' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $ctFindings

    # --- Tab 3: Urgent Fixes ---
    if ((SafeCount $urgentFix) -gt 0) {
        $urgentFix | Export-Excel -Path $xlFile -WorksheetName 'Urgent_Fixes' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText @(
            (New-ConditionalText 'DES' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'Trust' -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
        )
    }

    # --- Tab 4: Betroffene Systeme ---
    $ctRC4 = @(
        (New-ConditionalText 'RC4_ONLY'    -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
        (New-ConditionalText 'RC4_AES'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
        (New-ConditionalText 'DES_PRESENT' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
        (New-ConditionalText 'AES_ONLY'    -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
        (New-ConditionalText 'NOT_SET'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
    )
    if ((SafeCount $citrix) -gt 0) {
        $citrix | Export-Excel -Path $xlFile -WorksheetName 'Citrix' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $ctRC4
    }
    if ((SafeCount $deleg) -gt 0) {
        $deleg | Export-Excel -Path $xlFile -WorksheetName 'Delegation' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $ctRC4
    }

    # --- Tab 5: SMB (if available) ---
    if ((SafeCount $smbCsv) -gt 0) {
        $smbCsv | Export-Excel -Path $xlFile -WorksheetName 'SMB_Signing' -AutoSize -FreezeTopRow -BoldTopRow -Append
    }

    Write-Host "  Excel: $xlFile" -ForegroundColor Green
}
else {
    Write-Host "  Excel: ImportExcel nicht verfuegbar — nur HTML" -ForegroundColor DarkGray
}

#endregion

# Done
Write-Host "`n=== Report erstellt ===" -ForegroundColor Cyan
Write-Host "  $OutputPath" -ForegroundColor White
Write-Host ""
