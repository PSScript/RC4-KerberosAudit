#Requires -Version 5.1
<#
.SYNOPSIS
    Konsolidiertes RC4/Kerberos-Audit — ein Skript, fuenf Modi.
    Ersetzt Check-Server2025Defaults-v4, Prove-RC4Usage,
    Discover-RC4Environment und New-RC4Report(-DG).

.DESCRIPTION
    Ein Einstiegspunkt fuer den kompletten RC4-Audit-Workflow:

    -Mode Readiness : SMB/Kerberos/LDAP/NTLM-Defaults aller Server
                      (AD-Discovery + msDS-SupportedEncryptionTypes + WinRM)
    -Mode Prove     : Beweis aktiver RC4-Nutzung auf dem DC
                      (4768/4769/4770/4771, NTLM-Fallback, LDAP-Signing)
    -Mode Discover  : Heterogene Umgebung (Citrix/Igel/VMware/Linux),
                      Delegation, KDCSVC 201-209, NTLMv1, Kreuzpruefung
    -Mode Report    : Management-Report aus den CSVs eines Report-Ordners
                      (-ReportStyle Plain = XLSX+HTML | DG = Corporate HTML)
    -Mode Full      : Readiness + Prove + Discover, danach Report aus dem
                      Discover-Ergebnisordner

    Die Modi entsprechen 1:1 den bisherigen Einzelskripten — Ausgaben,
    CSV-Namen und Spalten bleiben identisch. Bestehende Runbooks
    funktionieren nach Austausch des Skriptnamens unveraendert.

.PARAMETER Mode
    Readiness | Prove | Discover | Report | Full. Standard: Full

.PARAMETER Hours
    Event-Log Zeitraum in Stunden (Prove/Discover). Standard: 24

.PARAMETER MaxEvents
    Max Events pro Abfrage (Prove/Discover). Standard: 1000
    (Hinweis: Prove-RC4Usage hatte frueher 500.)

.PARAMETER ReportPath
    Ausgabe-Wurzelordner. Standard: C:\Temp
    Readiness schreibt SMB_Kerberos_report_<ts>*.csv direkt hierhin,
    Discover erstellt RC4_<DOMAIN>_<ts>\ darunter.

.PARAMETER Scope
    (Readiness) DomainControllers | MemberServers | All | AllServers. Standard: All
    All = alle rollen-entdeckten Server (DC/Exchange/CA/Cluster/DFS/HyperV).
    AllServers = zusaetzlich JEDES aktivierte Server-OS-Computerkonto der Domaene
    (Phase 2 via WinRM auf allen Servern — SOC vorab informieren).

.PARAMETER KerberosScope
    (Readiness) DiscoveredOnly | AllServers | Full. Standard: DiscoveredOnly

.PARAMETER SkipRemoteCheck
    (Readiness) Nur Phase 1 + 1.5, kein WinRM.

.PARAMETER ExportCsv
    (Readiness) Zusaetzlicher CSV-Export-Pfad.

.PARAMETER CountOnly
    (Prove) Schnellmodus: nur Zaehlung via wevtutil.

.PARAMETER NoBootFilter
    (Prove) Boot-Fenster NICHT als Rauschen markieren. Standard: Events im
    Reboot-Fenster (Boot -2 min bis +BootWindowMinutes) werden ausgewiesen,
    aber nicht als Befund gezaehlt — sie sind by design (Dienste-Neustart,
    Wininit, gecachte Credentials).

.PARAMETER BootWindowMinutes
    (Prove) Nachlauf des Boot-Fensters in Minuten. Standard: 5.

.PARAMETER SkipEvents
    (Discover) Nur AD-Discovery, keine Event-Log-Analyse.

.PARAMETER ReassessFrom
    (Discover) Offline-Neubewertung aus einem vorherigen Report-Ordner.

.PARAMETER SendMail
    (Discover) ZIP-Report per E-Mail versenden (-MailTo/-MailFrom/-SmtpServer).

.PARAMETER ReportStyle
    (Report/Full) Plain = XLSX+HTML | DG = Corporate-Design-HTML. Standard: Plain

.PARAMETER ReportSource
    (Report) Ordner mit den CSVs (z.B. C:\Temp\RC4_CONTOSO_20260319_162051).
    Bei -Mode Full automatisch der Discover-Ergebnisordner.

.PARAMETER OutputPath
    (Report) Zielpfad des Reports. Standard: ReportSource.

.PARAMETER Author
    (Report, DG) Autor im Report-Kopf.

.PARAMETER DomainLabel
    (Report) Anzeigename der Domaene; sonst aus Ordnernamen erkannt.

.PARAMETER ImportOnly
    Laedt nur die Funktionen (Dot-Sourcing), fuehrt keinen Scan aus.

.PARAMETER DiscoverAll
    Breiten-Schalter: entspricht -Scope AllServers -KerberosScope AllServers.
    Mit -Mode Full: kompletter Audit ueber alle Server der Domaene.
    (KerberosScope Full — gesamte Domaene inkl. User/gMSA/Trusts — bleibt explizit.)

.PARAMETER CompareBefore
    (Compare) Vorher-Report: Pfad/Wildcard auf SMB_Kerberos_report_*.csv.
    Ohne Angabe: aeltester Hauptreport unter -ReportPath.

.PARAMETER CompareAfter
    (Compare) Nachher-Report. Ohne Angabe: neuester Hauptreport unter -ReportPath.
    -Mode Compare akkumuliert pro Einstellung was sich geaendert hat — ueber alle
    Server ("Was hat das Update umgestellt?"). Nur CSV-Auswertung, kein AD/WinRM.

.EXAMPLE
    .\Invoke-RC4Audit.ps1 -Mode Readiness
    .\Invoke-RC4Audit.ps1 -Mode Prove -Hours 168
    .\Invoke-RC4Audit.ps1 -Mode Discover -Hours 168 -MaxEvents 5000
    .\Invoke-RC4Audit.ps1 -Mode Discover -ReassessFrom 'C:\Temp\RC4_CONTOSO_20260319_162051'
    .\Invoke-RC4Audit.ps1 -Mode Report -ReportSource 'C:\Temp\RC4_CONTOSO_20260319_162051' -ReportStyle DG
    .\Invoke-RC4Audit.ps1 -Mode Full -Hours 168 -ReportStyle DG
    .\Invoke-RC4Audit.ps1 -Mode Full -Hours 168 -DiscoverAll -ReportStyle DG

.NOTES
    Datum   : 2026-07-30
    Version : 1.0 (Konsolidierung)
    Kontext : Zusammenfuehrung der vier RC4-Suite-Skripte in einen
              Einstiegspunkt. Prove und beide Report-Engines sind als
              gekapselte Modus-Funktionen eingebettet (lokale Helfer,
              keine Namenskonflikte); Discover-Helfer sind der
              gemeinsame Kanon auf Skriptebene.
    Referenz: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Parameter werden in den gekapselten Modus-Funktionen via dynamischem Scope verwendet (Invoke-Mode*)')]
param(
    [ValidateSet('Readiness', 'Prove', 'Discover', 'Report', 'Full', 'Compare')]
    [string]$Mode = 'Full',

    # Gemeinsam
    [int]$Hours = 24,
    [int]$MaxEvents = 1000,
    [string]$ReportPath = 'C:\Temp',

    # Readiness (ehem. Check-Server2025Defaults-v4)
    [ValidateSet('DomainControllers', 'MemberServers', 'All', 'AllServers')]
    [string]$Scope = 'All',
    [ValidateSet('DiscoveredOnly', 'AllServers', 'Full')]
    [string]$KerberosScope = 'DiscoveredOnly',
    [switch]$SkipRemoteCheck,
    [string]$ExportCsv,

    # Prove (ehem. Prove-RC4Usage)
    [switch]$CountOnly,
    [switch]$NoBootFilter,
    [int]$BootWindowMinutes = 5,

    # Discover (ehem. Discover-RC4Environment)
    [switch]$SkipEvents,
    [string]$ReassessFrom,
    [switch]$SendMail,
    [string]$MailTo,
    [string]$MailFrom,
    [string]$SmtpServer,

    # Report (ehem. New-RC4Report / New-RC4Report-DG)
    [ValidateSet('Plain', 'DG')]
    [string]$ReportStyle = 'Plain',
    [string]$ReportSource,
    [string]$OutputPath,
    [string]$Author = '',
    [string]$DomainLabel,

    [switch]$ImportOnly,

    # Breiten-Schalter: setzt Scope=AllServers und KerberosScope=AllServers
    [switch]$DiscoverAll,

    # Compare (Baseline-Diff zweier Readiness-Reports)
    [string]$CompareBefore,
    [string]$CompareAfter
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'

# -DiscoverAll: volle Breite (alle Server-OS-Konten + alle Server-Accounts im
# Kerberos-Audit). Bewusst NICHT KerberosScope=Full (gesamte Domaene, SOC-Alarm).
if ($DiscoverAll) {
    $Scope = 'AllServers'
    $KerberosScope = 'AllServers'
}

#region ============ DG CORPORATE DESIGN (Klassen, Modus Report -ReportStyle DG) ============

class DGColor {
    static [string]$Red        = "#C8102E"
    static [string]$DarkRed    = "#A00D24"
    static [string]$LightRed   = "#F5E6E9"
    static [string]$Grey       = "#4A4A4A"
    static [string]$LightGrey  = "#F5F5F5"
    static [string]$MidGrey    = "#E0E0E0"
    static [string]$Black      = "#1A1A1A"
    static [string]$Green      = "#2E7D32"
    static [string]$Amber      = "#D4A017"
    static [string]$White      = "#FFFFFF"
}

class DGHtml {
    [System.Text.StringBuilder]$sb

    DGHtml() { $this.sb = [System.Text.StringBuilder]::new(65536) }

    [void] Append([string]$text) { [void]$this.sb.Append($text) }
    [void] AppendLine([string]$text) { [void]$this.sb.AppendLine($text) }
    [string] ToString() { return $this.sb.ToString() }

    [void] Title([string]$text) { $this.AppendLine("<h1 class='dg-title'>$text</h1>") }
    [void] SubtitleRed([string]$text) { $this.AppendLine("<p class='dg-subtitle-red'>$text</p>") }
    [void] H1([string]$text) { $this.AppendLine("<h2 class='dg-h1'>$text</h2>") }
    [void] H2([string]$text) { $this.AppendLine("<h3 class='dg-h2'>$text</h3>") }
    [void] H3([string]$text) { $this.AppendLine("<h4 class='dg-h3'>$text</h4>") }
    [void] Body([string]$text) { $this.AppendLine("<p class='dg-body'>$text</p>") }
    [void] BodyBold([string]$text) { $this.AppendLine("<p class='dg-body'><strong>$text</strong></p>") }
    [void] Bullet([string]$text) { $this.AppendLine("<p class='dg-bullet'><span class='dg-sq'>&#9632;</span> $text</p>") }
    [void] Note([string]$text) { $this.AppendLine("<div class='dg-note'>$text</div>") }
    [void] Warning([string]$text) { $this.AppendLine("<div class='dg-note'><strong>&#9888;</strong> $text</div>") }
    [void] Code([string]$text) { $this.AppendLine("<pre class='dg-code'>$text</pre>") }
    [void] RedDivider() { $this.AppendLine("<hr class='dg-divider'/>") }
    [void] Spacer() { $this.AppendLine("<div style='height:12px'></div>") }
    [void] PageBreak() { $this.AppendLine("<div class='page-break'></div>") }

    [void] MetaTable([array]$rows) {
        $this.AppendLine("<table class='dg-meta'>")
        foreach ($row in $rows) {
            $label = $row[0]; $value = $row[1]
            $this.AppendLine("<tr><td class='dg-meta-label'><strong>$label</strong></td><td class='dg-meta-value'>$value</td></tr>")
        }
        $this.AppendLine("</table>")
    }

    [void] DataTable([string[]]$headers, [array]$rows) {
        $this.AppendLine("<table class='dg-table'>")
        $this.Append("<thead><tr>")
        foreach ($hdr in $headers) { $this.Append("<th>$hdr</th>") }
        $this.AppendLine("</tr></thead><tbody>")
        $i = 0
        foreach ($row in $rows) {
            $cls = if ($i % 2 -eq 1) { " class='alt'" } else { "" }
            $this.Append("<tr$cls>")
            $first = $true
            foreach ($cell in $row) {
                if ($first) { $this.Append("<td><strong>$cell</strong></td>"); $first = $false }
                else { $this.Append("<td>$cell</td>") }
            }
            $this.AppendLine("</tr>")
            $i++
        }
        $this.AppendLine("</tbody></table>")
    }

    [void] StatusBadge([string]$typ) {
        $color = switch ($typ) {
            'Fehler'      { [DGColor]::Red }
            'Warnung'     { [DGColor]::Amber }
            'Information' { [DGColor]::Green }
            default       { [DGColor]::Grey }
        }
        $this.Append("<span style='display:inline-block;background:${color};color:white;padding:1px 8px;border-radius:3px;font-size:8pt;font-weight:bold;margin-right:6px;'>$typ</span>")
    }

    [void] FindingCard([string]$nr, [string]$typ, [string]$titel, [hashtable]$fields) {
        $borderColor = switch ($typ) {
            'Fehler'      { [DGColor]::Red }
            'Warnung'     { [DGColor]::Amber }
            'Information' { [DGColor]::Green }
            default       { [DGColor]::MidGrey }
        }
        $this.AppendLine("<div class='dg-finding' style='border-left:4px solid ${borderColor};'>")
        $this.Append("<h4 class='dg-h3' style='margin-top:0;'>")
        $this.StatusBadge($typ)
        $this.AppendLine(" #${nr}: $titel</h4>")

        foreach ($key in @('Befund','Betroffene','Auswirkung','Mitigation','Seiteneffekte')) {
            if ($fields.ContainsKey($key) -and $fields[$key]) {
                $val = $fields[$key] -replace "`n", "<br/>"
                $labelColor = if ($key -eq 'Mitigation') { [DGColor]::DarkRed } else { [DGColor]::Grey }
                $this.AppendLine("<p class='dg-finding-label' style='color:${labelColor};'><strong>$key</strong></p>")
                $this.AppendLine("<p class='dg-finding-value'>$val</p>")
            }
        }
        $this.AppendLine("</div>")
    }

    [void] SummaryCard([string]$label, [string]$value, [string]$color) {
        $this.AppendLine("<div class='dg-summary-card'><div class='dg-summary-label'>$label</div><div class='dg-summary-value' style='color:${color};'>$value</div></div>")
    }
}

class DGDocument {
    [DGHtml]$Html
    [string]$Title
    [string]$Category1
    [string]$Category2
    [string]$Footer

    DGDocument([string]$title, [string]$cat1, [string]$cat2, [string]$footer) {
        $this.Html = [DGHtml]::new()
        $this.Title = $title
        $this.Category1 = $cat1
        $this.Category2 = $cat2
        $this.Footer = $footer
    }

    [string] Build() {
        $css = @"
<style>
@import url('https://fonts.googleapis.com/css2?family=Carlito:ital,wght@0,400;0,700;1,400;1,700&display=swap');
@page { size: A4 portrait; margin: 25mm 20mm 25mm 25mm; }
@media print {
    body { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    .dg-header { position: fixed; top: 0; left: 0; right: 0; }
    .page-break { page-break-before: always; }
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Carlito', Calibri, Arial, sans-serif;
    font-size: 10pt; line-height: 1.4;
    color: $([DGColor]::Grey);
    max-width: 210mm; margin: 0 auto; background: white;
}
.dg-header {
    background: $([DGColor]::Red); color: white;
    padding: 5mm 25mm; display: flex; justify-content: space-between; align-items: center;
}
.dg-header-left { font-weight: bold; font-size: 14pt; }
.dg-header-right { font-size: 9pt; text-align: right; }
.dg-content { padding: 8mm 20mm 15mm 25mm; }
.dg-footer {
    border-top: 0.75pt solid $([DGColor]::Red);
    padding-top: 3mm; margin-top: 8mm;
    display: flex; justify-content: space-between;
    font-size: 7.5pt; color: $([DGColor]::Grey);
}

.dg-title { font-size: 22pt; font-weight: bold; color: $([DGColor]::Black); margin-bottom: 4mm; margin-top: 15mm; }
.dg-subtitle-red { font-size: 16pt; font-weight: bold; color: $([DGColor]::Red); margin-bottom: 3mm; }
.dg-h1 { font-size: 16pt; font-weight: bold; color: $([DGColor]::Red); margin-top: 10mm; margin-bottom: 4mm; page-break-after: avoid; }
.dg-h2 { font-size: 13pt; font-weight: bold; color: $([DGColor]::Black); margin-top: 6mm; margin-bottom: 3mm; page-break-after: avoid; }
.dg-h3 { font-size: 11pt; font-weight: bold; color: $([DGColor]::DarkRed); margin-top: 4mm; margin-bottom: 2mm; page-break-after: avoid; }
.dg-body { font-size: 10pt; color: $([DGColor]::Grey); margin-bottom: 3mm; text-align: justify; }
.dg-bullet { font-size: 10pt; color: $([DGColor]::Grey); margin-bottom: 2mm; padding-left: 12mm; }
.dg-sq { color: $([DGColor]::Red); font-size: 8pt; margin-right: 2mm; }
.dg-note {
    font-size: 9.5pt; font-style: italic; color: $([DGColor]::Grey);
    background: $([DGColor]::LightRed); border-left: 2pt solid $([DGColor]::Red);
    padding: 6px 8px; margin: 3mm 0 3mm 5mm;
}
.dg-code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9pt; color: $([DGColor]::Black);
    background: #F8F8F8; border: 0.5pt solid $([DGColor]::MidGrey);
    padding: 6px 8px; margin: 2mm 0 3mm 5mm;
    white-space: pre-wrap; word-wrap: break-word;
}
.dg-divider { border: none; border-top: 2pt solid $([DGColor]::Red); margin: 5mm 0; }

.dg-table { width: 100%; border-collapse: collapse; margin: 3mm 0; font-size: 9pt; }
.dg-table th {
    background: $([DGColor]::Red); color: white; font-weight: bold;
    text-align: left; padding: 5px 6px; border: 0.75pt solid $([DGColor]::Red);
}
.dg-table td {
    padding: 5px 6px; border: 0.75pt solid $([DGColor]::Red);
    border-left: 0.4pt solid $([DGColor]::MidGrey); border-right: 0.4pt solid $([DGColor]::MidGrey);
    vertical-align: top;
}
.dg-table td:first-child { border-left: 0.75pt solid $([DGColor]::Red); }
.dg-table td:last-child { border-right: 0.75pt solid $([DGColor]::Red); }
.dg-table tbody tr.alt { background: $([DGColor]::LightGrey); }

.dg-meta { width: 100%; border-collapse: collapse; margin: 3mm 0; font-size: 9pt; }
.dg-meta td { padding: 4px 6px; border: 0.5pt solid $([DGColor]::Red); vertical-align: top; }
.dg-meta .dg-meta-label { width: 55mm; background: $([DGColor]::LightRed); font-weight: bold; color: $([DGColor]::Black); }
.dg-meta .dg-meta-value { color: $([DGColor]::Grey); }

.dg-summary-grid { display: flex; flex-wrap: wrap; gap: 8px; margin: 4mm 0; }
.dg-summary-card {
    flex: 1 1 120px; background: white; border: 1px solid $([DGColor]::MidGrey);
    border-radius: 4px; padding: 8px 12px; text-align: center; min-width: 120px;
}
.dg-summary-label { font-size: 8pt; color: $([DGColor]::Grey); text-transform: uppercase; letter-spacing: 0.5px; }
.dg-summary-value { font-size: 20pt; font-weight: bold; margin-top: 2px; }

.dg-finding {
    background: white; border: 1px solid $([DGColor]::MidGrey);
    border-radius: 4px; padding: 10px 14px; margin: 4mm 0;
    page-break-inside: avoid;
}
.dg-finding-label { font-size: 8.5pt; color: $([DGColor]::Grey); margin: 6px 0 1px 0; text-transform: uppercase; letter-spacing: 0.3px; }
.dg-finding-value { font-size: 9.5pt; color: $([DGColor]::Black); margin: 0 0 4px 0; white-space: pre-line; }

.dg-warn-red { color: $([DGColor]::Red); font-weight: bold; }
.dg-warn-amber { color: $([DGColor]::Amber); font-weight: bold; }
.dg-ok-green { color: $([DGColor]::Green); }
.page-break { page-break-before: always; height: 0; margin: 0; padding: 0; }
</style>
"@
        return @"
<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"><title>$($this.Title)</title>$css</head>
<body>
<div class='dg-header'>
    <div class='dg-header-left'>$($this.Title.Split(' ')[0])</div>
    <div class='dg-header-right'>$($this.Category1)<br/>$($this.Category2)</div>
</div>
<div class='dg-content'>
$($this.Html.ToString())
</div>
</body></html>
"@
    }

    [void] Save([string]$path) {
        [System.IO.File]::WriteAllText($path, $this.Build(), [System.Text.Encoding]::UTF8)
        $kb = [Math]::Round((Get-Item $path).Length / 1024, 1)
        Write-Host "  HTML: $path ($kb KB)" -ForegroundColor Green
    }
}

#endregion

#region ============ GEMEINSAME BASIS + DISCOVER-FUNKTIONEN ============
#region ============ HELPERS ============

$script:EncTypes = @{
    '0x1'='DES_CBC_CRC'; '0x3'='DES_CBC_MD5'; '0x11'='AES128'; '0x12'='AES256'
    '0x17'='RC4-HMAC'; '0x18'='RC4-HMAC-EXP'; '0xffffffff'='FAIL/NO-KEY'
    '1'='DES_CBC_CRC'; '3'='DES_CBC_MD5'; '17'='AES128'; '18'='AES256'
    '23'='RC4-HMAC'; '24'='RC4-HMAC-EXP'
}

function Get-EncLabel {
    param([string]$Value)
    $v = $Value.Trim().ToLower()
    if ($script:EncTypes.ContainsKey($v)) { return $script:EncTypes[$v] }
    return "Unknown ($Value)"
}

function Get-XmlField {
    param([xml]$EventXml, [string]$FieldName)
    try {
        $node = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
        if ($null -eq $node) { return $null }
        $val = $node.'#text'
        if ($null -eq $val) { return $node.InnerText }
        return $val
    } catch { return $null }
}

function Format-EventCount {
    param([int]$Count, [int]$Max)
    if ($Count -ge $Max) { return "$Count+ (MaxEvents erreicht — es gibt vermutlich mehr)" }
    return "$Count"
}

function Get-EncCategory {
    param([int]$Value)
    if ($Value -eq 0 -or $null -eq $Value) { return 'NOT_SET' }
    $hasDES = [bool]($Value -band 0x3)
    $hasRC4 = [bool]($Value -band 0x4)
    $hasAES = [bool](($Value -band 0x8) -or ($Value -band 0x10))
    if ($hasDES) { return 'DES_PRESENT' }
    if ($hasRC4 -and -not $hasAES) { return 'RC4_ONLY' }
    if ($hasRC4 -and $hasAES) { return 'RC4_AES' }
    if ($hasAES -and -not $hasRC4) { return 'AES_ONLY' }
    return 'UNKNOWN'
}

function Write-Status {
    param([string]$Label, [string]$Value, [string]$Color = 'White')
    if (-not $Color) { $Color = 'White' }
    Write-Host "  $($Label.PadRight(35)) : " -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function SafeCount {
    # Returns count that works with StrictMode and single objects
    param($Collection)
    if ($null -eq $Collection) { return 0 }
    if ($Collection -is [array]) { return $Collection.Length }
    return 1
}

function Get-Bewertung {
    param([string]$EncCategory, [string]$Role, $PasswordLastSet)
    $pwAge = if ($PasswordLastSet) {
        [math]::Round(((Get-Date) - $PasswordLastSet).TotalDays)
    } else { -1 }

    $encText = switch ($EncCategory) {
        'RC4_ONLY'    { 'Nur RC4 — kann kein AES. Wenn ein Server 2025 DC oder das April-2026-Update aktiv ist, schlaegt die Authentifizierung fehl.' }
        'RC4_AES'     { 'RC4 und AES erlaubt. Der KDC kann RC4 waehlen, insbesondere bei Constrained Delegation. Ziel: auf AES-only (Wert 24) setzen.' }
        'DES_PRESENT' { 'DES im Attribut — seit 2008 als unsicher eingestuft. Sofort auf AES-only aendern.' }
        'NOT_SET'     { 'Wert nicht gesetzt (0/NULL) — folgt dem Domain-Default. Ab April 2026 wird der Default auf AES-only geaendert. Bis dahin kann der KDC RC4 waehlen.' }
        'AES_ONLY'    { 'Nur AES — Zielzustand. Keine Aenderung noetig.' }
        default       { 'Unbekannter Wert — manuell pruefen.' }
    }

    $roleText = switch -Wildcard ($Role) {
        'Citrix-StoreFront' { 'StoreFront ist der erste Hop nach dem Benutzer. Ein RC4-Ticket hier betrifft alle Citrix-Sessions.' }
        'Citrix-DDC'        { 'Der Delivery Controller brokert Sessions per Kerberos. RC4 hier kann Session-Starts gelegentlich stoeren.' }
        'Citrix-VDA'        { 'VDA hostet die Benutzersitzung. RC4 betrifft den Zugriff auf Ressourcen innerhalb der Session (OWA, Shares).' }
        'NetScaler'         { 'NetScaler/ADC verwendet Constrained Delegation (S4U2Proxy). Die Encryption des delegierten Tickets haengt von diesem Account ab, nicht vom Benutzer.' }
        'Citrix-ServiceAccount' { 'Citrix Service Account mit SPN. Wenn RC4 im Attribut steht, kann der KDC RC4-Tickets fuer Citrix-Dienste ausstellen.' }
        'Igel'              { 'Igel Thin Client. Alte Firmware kann RC4 als Default in /etc/krb5.conf haben. Ueber UMS zentral auf AES umstellen.' }
        'Linux'             { 'Linux-System. Kerberos-Verhalten abhaengig von krb5.conf und Samba-Version. Ab Samba 4.13 AES unterstuetzt.' }
        'VMware*'           { 'VMware-System. vCenter AD-Integration und SSO Kerberos pruefen.' }
        'macOS'             { 'macOS 10.7+ unterstuetzt AES — in der Regel unproblematisch.' }
        default             { '' }
    }

    $pwText = ''
    if ($pwAge -gt 365) {
        $pwText = "Kennwort seit $pwAge Tagen nicht geaendert. AES-Keys werden erst bei Kennwortwechsel generiert — moeglicherweise keine AES-Keys vorhanden."
    }
    elseif ($pwAge -gt 180) {
        $pwText = "Kennwort $pwAge Tage alt."
    }

    $parts = @($encText)
    if ($roleText) { $parts += $roleText }
    if ($pwText) { $parts += $pwText }
    return ($parts -join ' ')
}

function Get-DelegationBewertung {
    param([string]$EncCategory, [string]$DelegationType, [string]$DelegateTo)
    $base = Get-Bewertung -EncCategory $EncCategory -Role 'Delegation' -PasswordLastSet $null

    $delegText = switch ($DelegationType) {
        'Unconstrained' { 'ACHTUNG: Unconstrained Delegation — dieser Account kann Tickets fuer JEDEN Dienst anfordern. Sicherheitsrisiko unabhaengig von RC4. Auf Constrained Delegation umstellen.' }
        'Constrained'   {
            $targets = ($DelegateTo -split ';' | ForEach-Object { $_.Trim() } | Select-Object -First 3) -join ', '
            "Constrained Delegation fuer: $targets. Die Encryption des delegierten Tickets haengt von diesem Account ab. Bei RC4 im Attribut kann der KDC RC4-Tickets fuer das Backend ausstellen."
        }
        default { '' }
    }

    if ($delegText) { return "$base $delegText" }
    return $base
}

function Export-ToCsv {
    param([array]$Data, [string]$Name)
    if ((SafeCount $Data) -eq 0) { return $null }
    $p = Join-Path $reportDir "${Name}.csv"
    $Data | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    return $p
}

#endregion

#region ============ PHASE 1: AD DISCOVERY ============

function Get-CitrixInfrastructure {
    [CmdletBinding()]
    param()
    Write-Host "`n=== CITRIX INFRASTRUKTUR ===" -ForegroundColor Yellow
    $results = @()

    # StoreFront / Delivery Controller / VDA by naming convention and SPN
    $patterns = @('*CTX*','*XA*','*XD*','*VDA*','*DDC*','*StoreFront*','*Citrix*','*SF-*','*NetScaler*')
    $found = @{}

    foreach ($pat in $patterns) {
        try {
            Get-ADComputer -Filter "Name -like '$pat'" -Properties msDS-SupportedEncryptionTypes, OperatingSystem, Description, PasswordLastSet, ServicePrincipalName -EA SilentlyContinue |
                ForEach-Object { if (-not $found.ContainsKey($_.Name)) { $found[$_.Name] = $_ } }
        } catch {}
    }

    # By Citrix-related SPNs
    try {
        Get-ADComputer -Filter { ServicePrincipalName -like "HTTP/*" } -Properties msDS-SupportedEncryptionTypes, OperatingSystem, Description, PasswordLastSet, ServicePrincipalName -EA SilentlyContinue |
            Where-Object { $_.Description -match 'Citrix|StoreFront|Delivery|XenApp|XenDesktop|VDA' -or $_.ServicePrincipalName -match 'Citrix' } |
            ForEach-Object { if (-not $found.ContainsKey($_.Name)) { $found[$_.Name] = $_ } }
    } catch {}

    foreach ($comp in $found.Values) {
        $enc = $comp.'msDS-SupportedEncryptionTypes'
        $cat = Get-EncCategory $enc
        $role = 'Citrix'
        if ($comp.Name -match 'DDC|Controller') { $role = 'Citrix-DDC' }
        elseif ($comp.Name -match 'SF|StoreFront') { $role = 'Citrix-StoreFront' }
        elseif ($comp.Name -match 'VDA|XA') { $role = 'Citrix-VDA' }
        elseif ($comp.Name -match 'NetScaler|ADC|NS') { $role = 'NetScaler' }

        $results += [PSCustomObject]@{
            Name = $comp.Name; Role = $role; OS = $comp.OperatingSystem
            EncValue = $enc; EncCategory = $cat; PasswordLastSet = $comp.PasswordLastSet
            SPNs = ($comp.ServicePrincipalName -join '; ')
            Bewertung = (Get-Bewertung -EncCategory $cat -Role $role -PasswordLastSet $comp.PasswordLastSet)
            ADAttribute = 'msDS-SupportedEncryptionTypes'
            FixCmd = "Set-ADComputer '$($comp.Name)' -KerberosEncryptionType AES128,AES256"
        }
    }

    # Citrix Service Accounts (User accounts with Citrix SPNs)
    try {
        Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties msDS-SupportedEncryptionTypes, ServicePrincipalName, PasswordLastSet -EA SilentlyContinue |
            Where-Object { $_.ServicePrincipalName -match 'HTTP|Citrix|StoreFront' } |
            ForEach-Object {
                $enc = $_.'msDS-SupportedEncryptionTypes'
                $results += [PSCustomObject]@{
                    Name = $_.Name; Role = 'Citrix-ServiceAccount'; OS = 'N/A'
                    EncValue = $enc; EncCategory = (Get-EncCategory $enc)
                    PasswordLastSet = $_.PasswordLastSet
                    SPNs = ($_.ServicePrincipalName -join '; ')
                    Bewertung = (Get-Bewertung -EncCategory (Get-EncCategory $enc) -Role 'Citrix-ServiceAccount' -PasswordLastSet $_.PasswordLastSet)
                    ADAttribute = 'msDS-SupportedEncryptionTypes'
                    FixCmd = "Set-ADUser '$($_.Name)' -KerberosEncryptionType AES128,AES256"
                }
            }
    } catch {}

    Write-Status "Citrix-Systeme gefunden" "$((SafeCount $results))" $(if ((SafeCount $results) -gt 0) {'Cyan'} else {'DarkGray'})
    $rc4 = @($results | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
    Write-Status "davon mit RC4/DES im Attribut" "$((SafeCount $rc4))" $(if ((SafeCount $rc4) -gt 0) {'Yellow'} else {'Green'})
    return $results
}

function Get-IgelDevices {
    [CmdletBinding()]
    param()
    Write-Host "`n=== IGEL THIN CLIENTS ===" -ForegroundColor Yellow
    $results = @()

    # By naming convention
    $patterns = @('*IGEL*','*IGL*','*TC-*','*THIN*','*ThinClient*')
    $found = @{}

    foreach ($pat in $patterns) {
        try {
            Get-ADComputer -Filter "Name -like '$pat'" -Properties msDS-SupportedEncryptionTypes, OperatingSystem, Description, PasswordLastSet -EA SilentlyContinue |
                ForEach-Object { if (-not $found.ContainsKey($_.Name)) { $found[$_.Name] = $_ } }
        } catch {}
    }

    # By OS containing Linux/IGEL
    try {
        Get-ADComputer -Filter { OperatingSystem -like "*IGEL*" -or OperatingSystem -like "*Linux*thin*" } -Properties msDS-SupportedEncryptionTypes, OperatingSystem, Description, PasswordLastSet -EA SilentlyContinue |
            ForEach-Object { if (-not $found.ContainsKey($_.Name)) { $found[$_.Name] = $_ } }
    } catch {}

    # By Description containing Igel
    try {
        Get-ADComputer -Filter { Description -like "*IGEL*" -or Description -like "*Thin Client*" } -Properties msDS-SupportedEncryptionTypes, OperatingSystem, Description, PasswordLastSet -EA SilentlyContinue |
            ForEach-Object { if (-not $found.ContainsKey($_.Name)) { $found[$_.Name] = $_ } }
    } catch {}

    foreach ($comp in $found.Values) {
        $enc = $comp.'msDS-SupportedEncryptionTypes'
        $results += [PSCustomObject]@{
            Name = $comp.Name; Role = 'Igel'; OS = $comp.OperatingSystem
            EncValue = $enc; EncCategory = (Get-EncCategory $enc)
            PasswordLastSet = $comp.PasswordLastSet
            Description = $comp.Description
            Bewertung = (Get-Bewertung -EncCategory (Get-EncCategory $enc) -Role 'Igel' -PasswordLastSet $comp.PasswordLastSet)
            RiskNote = 'Pruefen: /etc/krb5.conf default_tgs_enctypes auf dem Geraet'
        }
    }

    Write-Status "Igel/Thin Clients gefunden" "$((SafeCount $results))" $(if ((SafeCount $results) -gt 0) {'Cyan'} else {'DarkGray'})
    return $results
}

function Get-NonWindowsDevices {
    [CmdletBinding()]
    param()
    Write-Host "`n=== NON-WINDOWS / APPLIANCES ===" -ForegroundColor Yellow
    $results = @()

    # Linux, macOS, VMware, Appliances by OS
    $filters = @(
        @{ Filter='OperatingSystem -like "*Linux*"'; Role='Linux' }
        @{ Filter='OperatingSystem -like "*Ubuntu*"'; Role='Linux' }
        @{ Filter='OperatingSystem -like "*Red Hat*"'; Role='Linux' }
        @{ Filter='OperatingSystem -like "*CentOS*"'; Role='Linux' }
        @{ Filter='OperatingSystem -like "*SUSE*"'; Role='Linux' }
        @{ Filter='OperatingSystem -like "*Debian*"'; Role='Linux' }
        @{ Filter='OperatingSystem -like "*Mac*"'; Role='macOS' }
        @{ Filter='OperatingSystem -like "*VMware*"'; Role='VMware' }
        @{ Filter='OperatingSystem -like "*ESXi*"'; Role='VMware-ESXi' }
        @{ Filter='OperatingSystem -like "*Appliance*"'; Role='Appliance' }
    )

    $found = @{}
    foreach ($f in $filters) {
        try {
            Get-ADComputer -Filter $f.Filter -Properties msDS-SupportedEncryptionTypes, OperatingSystem, PasswordLastSet -EA SilentlyContinue |
                ForEach-Object {
                    if (-not $found.ContainsKey($_.Name)) {
                        $found[$_.Name] = @{ Comp=$_; Role=$f.Role }
                    }
                }
        } catch {}
    }

    # Devices without Windows in OS (catch-all for unknown)
    try {
        Get-ADComputer -Filter { OperatingSystem -notlike "*Windows*" -and OperatingSystem -like "*" } -Properties msDS-SupportedEncryptionTypes, OperatingSystem, PasswordLastSet -EA SilentlyContinue |
            ForEach-Object {
                if (-not $found.ContainsKey($_.Name)) {
                    $found[$_.Name] = @{ Comp=$_; Role='Non-Windows' }
                }
            }
    } catch {}

    foreach ($item in $found.Values) {
        $comp = $item.Comp; $enc = $comp.'msDS-SupportedEncryptionTypes'
        $encCat = Get-EncCategory $enc
        $results += [PSCustomObject]@{
            Name = $comp.Name; Role = $item.Role; OS = $comp.OperatingSystem
            EncValue = $enc; EncCategory = $encCat
            PasswordLastSet = $comp.PasswordLastSet
            Bewertung = (Get-Bewertung -EncCategory $encCat -Role $item.Role -PasswordLastSet $comp.PasswordLastSet)
            RiskNote = switch ($item.Role) {
                'Linux'       { 'Pruefen: /etc/krb5.conf + Samba-Version + Keytab' }
                'VMware'      { 'Pruefen: vCenter AD-Integration und SSO Kerberos' }
                'VMware-ESXi' { 'Pruefen: ESXi AD-Join und Kerberos-Faehigkeit' }
                'macOS'       { 'macOS 10.7+ unterstuetzt AES — i.d.R. unproblematisch' }
                default       { 'Pruefen: Kerberos-Faehigkeit und Encryption Support' }
            }
        }
    }

    Write-Status "Non-Windows Geraete" "$((SafeCount $results))" $(if ((SafeCount $results) -gt 0) {'Cyan'} else {'DarkGray'})
    $byRole = $results | Group-Object Role
    foreach ($g in $byRole) { Write-Status "  $($g.Name)" "$($g.Count)" 'DarkGray' }
    return $results
}

function Get-DelegationAccounts {
    [CmdletBinding()]
    param()
    Write-Host "`n=== DELEGATION / PROXY ACCOUNTS ===" -ForegroundColor Yellow
    $results = @()

    # Computer accounts with Constrained Delegation
    try {
        Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } `
            -Properties msDS-SupportedEncryptionTypes, msDS-AllowedToDelegateTo, OperatingSystem, PasswordLastSet, TrustedForDelegation -EA SilentlyContinue |
            ForEach-Object {
                $enc = $_.'msDS-SupportedEncryptionTypes'
                $encCat = Get-EncCategory $enc
                $delType = if ($_.TrustedForDelegation) {'Unconstrained'} else {'Constrained'}
                $delTo = ($_.'msDS-AllowedToDelegateTo' -join '; ')
                $results += [PSCustomObject]@{
                    Name = $_.Name; Type = 'Computer'; OS = $_.OperatingSystem
                    EncValue = $enc; EncCategory = $encCat
                    DelegationType = $delType
                    DelegateTo = $delTo
                    PasswordLastSet = $_.PasswordLastSet
                    Bewertung = (Get-DelegationBewertung -EncCategory $encCat -DelegationType $delType -DelegateTo $delTo)
                    FixCmd = "Set-ADComputer '$($_.Name)' -KerberosEncryptionType AES128,AES256"
                }
            }
    } catch {}

    # User accounts with Constrained Delegation
    try {
        Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } `
            -Properties msDS-SupportedEncryptionTypes, msDS-AllowedToDelegateTo, PasswordLastSet, TrustedForDelegation -EA SilentlyContinue |
            ForEach-Object {
                $enc = $_.'msDS-SupportedEncryptionTypes'
                $encCat = Get-EncCategory $enc
                $delType = if ($_.TrustedForDelegation) {'Unconstrained'} else {'Constrained'}
                $delTo = ($_.'msDS-AllowedToDelegateTo' -join '; ')
                $results += [PSCustomObject]@{
                    Name = $_.SamAccountName; Type = 'ServiceAccount'; OS = 'N/A'
                    EncValue = $enc; EncCategory = $encCat
                    DelegationType = $delType
                    DelegateTo = $delTo
                    PasswordLastSet = $_.PasswordLastSet
                    Bewertung = (Get-DelegationBewertung -EncCategory $encCat -DelegationType $delType -DelegateTo $delTo)
                    FixCmd = "Set-ADUser '$($_.SamAccountName)' -KerberosEncryptionType AES128,AES256"
                }
            }
    } catch {}

    # Unconstrained Delegation (computers)
    try {
        Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties msDS-SupportedEncryptionTypes, OperatingSystem, PasswordLastSet -EA SilentlyContinue |
            Where-Object { $_.Name -notmatch 'DC|dc' } |
            ForEach-Object {
                $enc = $_.'msDS-SupportedEncryptionTypes'
                if (-not ($results | Where-Object { $_.Name -eq $_.Name })) {
                    $encCat = Get-EncCategory $enc
                    $results += [PSCustomObject]@{
                        Name = $_.Name; Type = 'Computer'; OS = $_.OperatingSystem
                        EncValue = $enc; EncCategory = $encCat
                        DelegationType = 'Unconstrained'
                        DelegateTo = 'ANY (Unconstrained!)'
                        PasswordLastSet = $_.PasswordLastSet
                        Bewertung = (Get-DelegationBewertung -EncCategory $encCat -DelegationType 'Unconstrained' -DelegateTo 'ANY')
                        FixCmd = "Set-ADComputer '$($_.Name)' -KerberosEncryptionType AES128,AES256"
                    }
                }
            }
    } catch {}

    Write-Status "Delegation-Accounts" "$((SafeCount $results))" $(if ((SafeCount $results) -gt 0) {'Cyan'} else {'DarkGray'})
    $rc4 = @($results | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
    Write-Status "davon mit RC4/DES" "$((SafeCount $rc4))" $(if ((SafeCount $rc4) -gt 0) {'Red'} else {'Green'})
    $unconst = @($results | Where-Object { $_.DelegationType -eq 'Unconstrained' })
    if ((SafeCount $unconst) -gt 0) {
        Write-Status "UNCONSTRAINED Delegation (!)" "$((SafeCount $unconst))" 'Red'
    }
    return $results
}

function Get-KerberosGPOPolicy {
    [CmdletBinding()]
    param()
    Write-Host "`n=== KERBEROS GPO POLICY ===" -ForegroundColor Yellow

    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $value = $null
    try { $value = (Get-ItemProperty -Path $regPath -Name 'SupportedEncryptionTypes' -EA Stop).SupportedEncryptionTypes } catch {}

    $result = [PSCustomObject]@{
        Server = $env:COMPUTERNAME
        RegistryPath = "$regPath\SupportedEncryptionTypes"
        GPOName = 'Network security: Configure encryption types allowed for Kerberos'
        Value = $value
        ValueHex = if ($value) { "0x{0:X}" -f $value } else { 'NOT SET' }
        HasDES = if ($value) { [bool]($value -band 0x3) } else { $false }
        HasRC4 = if ($value) { [bool]($value -band 0x4) } else { $false }
        HasAES128 = if ($value) { [bool]($value -band 0x8) } else { $false }
        HasAES256 = if ($value) { [bool]($value -band 0x10) } else { $false }
        Recommendation = ''
    }

    if ($null -eq $value) {
        $result.Recommendation = 'Nicht konfiguriert — folgt OS-Default. Ab April 2026 aendert sich der Default auf AES-only (CVE-2026-20833).'
        $result | Add-Member -NotePropertyName 'Bewertung' -NotePropertyValue 'GPO ist nicht explizit konfiguriert. Der Domain Controller verwendet den OS-Default. Aktuell erlaubt das RC4. Ab April 2026 wird der Default durch ein Windows Update auf AES-only geaendert — alle Accounts mit Wert 0 (NOT SET) werden dann als AES-only behandelt.'
        Write-Status "Kerberos GPO" "NOT SET (OS-Default)" 'DarkGray'
    }
    elseif ($value -eq 2147483647) {
        $result.Recommendation = 'ALLES erlaubt inkl. DES — Ziel: 2147483644 (ohne DES) oder 2147483640 (AES-only)'
        $result | Add-Member -NotePropertyName 'Bewertung' -NotePropertyValue 'GPO erlaubt alle Verschluesselungstypen einschliesslich DES. DES ist seit 2008 als unsicher eingestuft. Empfehlung: sofort auf 2147483644 (DES entfernen, RC4 im Uebergang belassen) oder direkt auf 2147483640 (AES-only) wenn alle Accounts bereinigt sind.'
        Write-Status "Kerberos GPO" "$value (DES+RC4+AES — zu offen)" 'Red'
    }
    elseif ($value -band 0x3) {
        $result.Recommendation = 'DES noch erlaubt — DES seit Jahrzehnten gebrochen. Sofort entfernen.'
        $result | Add-Member -NotePropertyName 'Bewertung' -NotePropertyValue 'GPO erlaubt DES-Verschluesselung. DES ist kryptographisch gebrochen und stellt ein Sicherheitsrisiko dar. Empfehlung: GPO-Wert auf 2147483644 (DES entfernen) oder 2147483640 (AES-only) aendern.'
        Write-Status "Kerberos GPO" "$value (DES erlaubt)" 'Red'
    }
    elseif ($value -band 0x4) {
        $result.Recommendation = 'RC4 noch erlaubt — Uebergang: OK, Ziel: 2147483640 (AES-only). Deadline: April 2026.'
        $result | Add-Member -NotePropertyName 'Bewertung' -NotePropertyValue 'GPO erlaubt RC4 und AES. Das ist ein akzeptabler Uebergangszustand. RC4 sollte erst entfernt werden (Wert 2147483640) wenn alle Computer- und Service-Accounts auf AES-only (Wert 24) umgestellt und deren Kennwoerter rotiert sind. Deadline: vor April 2026.'
        Write-Status "Kerberos GPO" "$value (RC4+AES)" 'Yellow'
    }
    else {
        $result.Recommendation = 'AES-only — Zielzustand erreicht.'
        $result | Add-Member -NotePropertyName 'Bewertung' -NotePropertyValue 'GPO erlaubt nur AES-Verschluesselung. Zielzustand erreicht. Keine Aenderung noetig.'
        Write-Status "Kerberos GPO" "$value (AES-only)" 'Green'
    }

    Write-Host "    -> GPO: $($result.GPOName)" -ForegroundColor DarkGray
    Write-Host "    -> Reg: $($result.RegistryPath)" -ForegroundColor DarkGray
    return $result
}

#endregion

#region ============ PHASE 2: EVENT CORRELATION ============

function Get-RC4TicketsBySystem {
    [CmdletBinding()]
    param(
        [int]$MsBack,
        [int]$Max,
        [array]$KnownSystems  # names to highlight
    )
    Write-Host "`n=== RC4 TICKET-KORRELATION ===" -ForegroundColor Yellow

    $allEvents = @()

    # --- 4769: RC4 Service Tickets ---
    Write-Host "  Event 4769 (RC4 Service Tickets)..." -NoNewline
    $xml4769 = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) &lt;= {0}]]] and *[EventData[Data[@Name=''TicketEncryptionType'']=''0x17'']]</Select></Query></QueryList>' -f $MsBack
    try {
        $raw = Get-WinEvent -FilterXml $xml4769 -MaxEvents $Max -EA Stop
        Write-Host " $(Format-EventCount (SafeCount $raw) $Max)" -ForegroundColor $(if ((SafeCount $raw) -gt 0) {'Red'} else {'Green'})
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $svc = Get-XmlField $x 'ServiceName'
            $acct = Get-XmlField $x 'TargetUserName'
            $ip = Get-XmlField $x 'IpAddress'
            $isKnown = $false
            foreach ($sys in $KnownSystems) { if ($svc -match [regex]::Escape($sys) -or $ip -match [regex]::Escape($sys)) { $isKnown = $true; break } }
            $allEvents += [PSCustomObject]@{
                Time = $evt.TimeCreated; EventID = 4769; Type = 'RC4_ServiceTicket'
                Account = $acct; Service = $svc; EncType = 'RC4-HMAC (0x17)'
                ClientIP = $ip; IsKnownSystem = $isKnown
                SystemMatch = if ($isKnown) { ($KnownSystems | Where-Object { $svc -match [regex]::Escape($_) -or $ip -match [regex]::Escape($_) }) -join ',' } else { '' }
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') { Write-Host " 0" -ForegroundColor Green }
        else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # --- 4770: RC4 Renewals ---
    Write-Host "  Event 4770 (RC4 Renewals)..." -NoNewline
    $xml4770 = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4770) and TimeCreated[timediff(@SystemTime) &lt;= {0}]]] and *[EventData[Data[@Name=''TicketEncryptionType'']=''0x17'']]</Select></Query></QueryList>' -f $MsBack
    try {
        $raw = Get-WinEvent -FilterXml $xml4770 -MaxEvents $Max -EA Stop
        Write-Host " $(Format-EventCount (SafeCount $raw) $Max)" -ForegroundColor $(if ((SafeCount $raw) -gt 0) {'Red'} else {'Green'})
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $allEvents += [PSCustomObject]@{
                Time = $evt.TimeCreated; EventID = 4770; Type = 'RC4_Renewal'
                Account = (Get-XmlField $x 'TargetUserName')
                Service = (Get-XmlField $x 'ServiceName')
                EncType = 'RC4-HMAC (0x17)'
                ClientIP = (Get-XmlField $x 'IpAddress')
                IsKnownSystem = $false; SystemMatch = ''
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') { Write-Host " 0" -ForegroundColor Green }
        else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # --- 4771: Pre-Auth Failures ---
    Write-Host "  Event 4771 (Pre-Auth Fehler)..." -NoNewline
    $xml4771 = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4771) and TimeCreated[timediff(@SystemTime) &lt;= {0}]]]</Select></Query></QueryList>' -f $MsBack
    $preAuthFails = @()
    try {
        $raw = Get-WinEvent -FilterXml $xml4771 -MaxEvents $Max -EA Stop
        Write-Host " $(Format-EventCount (SafeCount $raw) $Max)" -ForegroundColor $(if ((SafeCount $raw) -gt 50) {'Red'} elseif ((SafeCount $raw) -gt 0) {'Yellow'} else {'Green'})
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $preAuthFails += [PSCustomObject]@{
                Time = $evt.TimeCreated; EventID = 4771; Type = 'PreAuth_Fail'
                Account = (Get-XmlField $x 'TargetUserName')
                Service = ''; EncType = ''
                ClientIP = (Get-XmlField $x 'IpAddress')
                Status = (Get-XmlField $x 'Status')
                IsKnownSystem = $false; SystemMatch = ''
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') { Write-Host " 0" -ForegroundColor Green }
        else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # --- 4625: Failed Logon ---
    Write-Host "  Event 4625 (Failed Logon)..." -NoNewline
    $xml4625 = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= {0}]]]</Select></Query></QueryList>' -f $MsBack
    $logonFails = @()
    try {
        $raw = Get-WinEvent -FilterXml $xml4625 -MaxEvents $Max -EA Stop
        Write-Host " $(Format-EventCount (SafeCount $raw) $Max)" -ForegroundColor $(if ((SafeCount $raw) -gt 100) {'Red'} elseif ((SafeCount $raw) -gt 0) {'Yellow'} else {'Green'})
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $logonFails += [PSCustomObject]@{
                Time = $evt.TimeCreated; EventID = 4625; Type = 'Logon_Fail'
                Account = (Get-XmlField $x 'TargetUserName')
                AuthPackage = (Get-XmlField $x 'AuthenticationPackageName')
                Workstation = (Get-XmlField $x 'WorkstationName')
                ClientIP = (Get-XmlField $x 'IpAddress')
                Status = (Get-XmlField $x 'Status')
                SubStatus = (Get-XmlField $x 'SubStatus')
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') { Write-Host " 0" -ForegroundColor Green }
        else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # --- 4740: Lockouts ---
    Write-Host "  Event 4740 (Account Lockouts)..." -NoNewline
    $xml4740 = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) &lt;= {0}]]]</Select></Query></QueryList>' -f $MsBack
    $lockouts = @()
    try {
        $raw = Get-WinEvent -FilterXml $xml4740 -MaxEvents $Max -EA Stop
        Write-Host " $(Format-EventCount (SafeCount $raw) $Max)" -ForegroundColor $(if ((SafeCount $raw) -gt 20) {'Red'} elseif ((SafeCount $raw) -gt 0) {'Yellow'} else {'Green'})
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $lockouts += [PSCustomObject]@{
                Time = $evt.TimeCreated; EventID = 4740; Type = 'Lockout'
                Account = (Get-XmlField $x 'TargetUserName')
                CallerComputer = (Get-XmlField $x 'SubjectUserName')
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') { Write-Host " 0" -ForegroundColor Green }
        else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # --- Korrelation: PreAuth → Lockout (120s Fenster) ---
    Write-Host "`n  --- Korrelation: Kerberos-Fehler → Lockout ---" -ForegroundColor Cyan
    $correlated = @()
    foreach ($lo in $lockouts) {
        $matches = $preAuthFails | Where-Object {
            $_.Account -eq $lo.Account -and
            [math]::Abs(($_.Time - $lo.Time).TotalSeconds) -le 120
        }
        if ($matches) {
            $m = @($matches)[0]
            $correlated += [PSCustomObject]@{
                Account = $lo.Account
                LockoutTime = $lo.Time
                KerbFailTime = $m.Time
                KerbStatus = $m.Status
                DeltaSeconds = [math]::Round(($lo.Time - $m.Time).TotalSeconds)
                CallerComputer = $lo.CallerComputer
                ClientIP = $m.ClientIP
            }
        }
    }

    if ((SafeCount $correlated) -gt 0) {
        Write-Status "Korrelierte Lockouts (120s)" "$((SafeCount $correlated))" 'Red'
        foreach ($co in ($correlated | Select-Object -First 5)) {
            Write-Host "    $($co.Account.PadRight(25)) Kerb: $($co.KerbFailTime.ToString('HH:mm:ss')) → Lock: $($co.LockoutTime.ToString('HH:mm:ss')) ($($co.DeltaSeconds)s)" -ForegroundColor Red
        }
    } else {
        Write-Status "Korrelierte Lockouts" "0 — keine Fallback-Kette erkannt" 'Green'
    }

    # --- Failed Logons by source (Citrix/Kemp/Gateway identification) ---
    if ((SafeCount $logonFails) -gt 0) {
        Write-Host "`n  --- Top Quellen fehlgeschlagener Anmeldungen ---" -ForegroundColor Cyan
        $logonFails | Group-Object Workstation | Sort-Object Count -Descending | Select-Object -First 10 |
            ForEach-Object { Write-Status "  $($_.Name)" "$($_.Count)" 'Yellow' }
    }

    return @{
        RC4Tickets = $allEvents
        PreAuthFails = $preAuthFails
        LogonFails = $logonFails
        Lockouts = $lockouts
        Correlated = $correlated
    }
}

function Get-KdcsvcAuditEvents {
    <#
    .SYNOPSIS
        Prueft die neuen KDCSVC Audit Events 201-209 (seit Januar 2026 CU).
        Diese Events zeigen praezise welche Accounts/Dienste im April fehlschlagen werden.
    #>
    [CmdletBinding()]
    param([int]$Max = 500)

    Write-Host "`n=== KDCSVC RC4 AUDIT (System Log, seit Januar 2026 CU) ===" -ForegroundColor Yellow

    $kdcEvents = @()
    $eventMap = @{
        201='RC4 erkannt: Client bietet nur RC4, Service hat kein msDS (Audit)'
        202='RC4 erkannt: Service Account hat keine AES-Keys, msDS nicht definiert (Audit)'
        203='RC4 BLOCKIERT: Client nur RC4, Service kein msDS (Enforcement)'
        204='RC4 BLOCKIERT: Service ohne AES-Keys, msDS nicht definiert (Enforcement)'
        205='Unsichere Algorithmen (RC4/DES) in Domain Policy DefaultDomainSupportedEncTypes'
        206='RC4 erkannt: Service hat nur RC4-Keys (Audit)'
        207='RC4 erkannt: Service Account hat msDS aber keine AES-Keys (Audit)'
        209='RC4 erkannt wie 201 aber in Enforcement'
    }

    try {
        $raw = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Kdcsvc'
            Id = 201,202,203,204,205,206,207,209
        } -MaxEvents $Max -EA Stop)

        Write-Host "  KDCSVC Events: $(Format-EventCount $raw.Count $Max)" -ForegroundColor $(if ($raw.Count -gt 0) {'Red'} else {'Green'})

        foreach ($evt in $raw) {
            $msg = $evt.Message
            # Extract account name from message if possible
            $acctMatch = [regex]::Match($msg, '(?:account|Account|Konto)[\s:]+(\S+)')
            $acct = if ($acctMatch.Success) { $acctMatch.Groups[1].Value } else { '' }

            $kdcEvents += [PSCustomObject]@{
                Time      = $evt.TimeCreated
                EventID   = $evt.Id
                Bedeutung = $eventMap[[int]$evt.Id]
                Account   = $acct
                Message   = $msg.Substring(0, [Math]::Min(200, $msg.Length))
            }
        }

        if ($raw.Count -gt 0) {
            Write-Host ""
            $raw | Group-Object Id | Sort-Object Name | ForEach-Object {
                $desc = if ($eventMap[[int]$_.Name]) { $eventMap[[int]$_.Name] } else { 'Unbekannt' }
                $color = if ($_.Name -in @('203','204','209')) {'Red'} else {'Yellow'}
                Write-Host "  Event $($_.Name): $($_.Count)x — $desc" -ForegroundColor $color
            }
            Write-Host ""
            Write-Host "  ACHTUNG: Diese Events zeigen was im April 2026 fehlschlagen wird!" -ForegroundColor Red
            Write-Host "  Event 201/202/206/207 = Audit (Warnung). Event 203/204/209 = Blockiert." -ForegroundColor Red
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine|nicht gefunden') {
            Write-Host "  KDCSVC Events: 0 — keine RC4-Risiken durch den neuen Audit erkannt" -ForegroundColor Green
        }
        elseif ($_.Exception.Message -match 'not a valid log|kein gueltiges Protokoll|Quellname.*nicht gefunden') {
            Write-Host "  KDCSVC Provider nicht verfuegbar — Januar 2026 CU noch nicht installiert?" -ForegroundColor DarkGray
            Write-Host "  Pruefen: Get-HotFix | Where-Object { \$_.InstalledOn -ge '2026-01-13' }" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  KDCSVC Fehler: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    # Registry: RC4DefaultDisablementPhase
    Write-Host ""
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $phase = $null
    try { $phase = (Get-ItemProperty -Path $regPath -Name 'RC4DefaultDisablementPhase' -EA Stop).RC4DefaultDisablementPhase } catch {}

    $phaseLabels = @{ 0='Legacy (keine Aenderung)'; 1='Audit (Januar 2026 Default)'; 2='Enforcement simulieren (April-Verhalten)' }
    $phaseLabel = if ($null -eq $phase) { 'Nicht gesetzt (OS-Default)' } elseif ($phaseLabels[$phase]) { "$phase = $($phaseLabels[$phase])" } else { "$phase = Unbekannt" }

    Write-Host "  RC4DefaultDisablementPhase: $phaseLabel" -ForegroundColor $(if ($phase -eq 2) {'Red'} elseif ($phase -eq 1) {'Yellow'} else {'DarkGray'})

    return @{
        Events = $kdcEvents
        Phase = $phase
        CUInstalled = ($kdcEvents.Count -gt 0 -or $null -ne $phase)
    }
}

function Get-NTLMv1Usage {
    <#
    .SYNOPSIS
        Erkennt NTLMv1 vs NTLMv2 in fehlgeschlagenen Anmeldungen.
        NTLMv1 ist kryptographisch gebrochen (Mandiant Rainbow Tables).
    #>
    [CmdletBinding()]
    param([int]$MsBack, [int]$Max = 1000)

    Write-Host "`n=== NTLMv1 vs NTLMv2 ERKENNUNG ===" -ForegroundColor Yellow

    # Event 4624 (Success) mit LmPackageName zeigt welche NTLM-Version verwendet wird
    $xml = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK]]] and *[EventData[Data[@Name=''AuthenticationPackageName'']=''NTLM'']]</Select></Query></QueryList>'.Replace('MSBACK', $MsBack)

    $ntlmV1 = 0; $ntlmV2 = 0; $ntlmUnknown = 0
    $v1Accounts = @{}

    try {
        $raw = @(Get-WinEvent -FilterXml $xml -MaxEvents $Max -EA Stop)
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $lmPkg = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'LmPackageName' }).'#text' } catch { $null }
            $acct  = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' } catch { '?' }
            $ws    = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text' } catch { '?' }

            if ($lmPkg -match 'V1' -or $lmPkg -match 'LM') {
                $ntlmV1++
                $key = "$acct|$ws"
                if (-not $v1Accounts.ContainsKey($key)) { $v1Accounts[$key] = 0 }
                $v1Accounts[$key]++
            }
            elseif ($lmPkg -match 'V2') { $ntlmV2++ }
            else { $ntlmUnknown++ }
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found|Es wurden keine') {
            Write-Host "  Fehler: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    Write-Host "  NTLMv2 Anmeldungen  : $ntlmV2" -ForegroundColor $(if ($ntlmV2 -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  NTLMv1 Anmeldungen  : $ntlmV1" -ForegroundColor $(if ($ntlmV1 -gt 0) {'Red'} else {'Green'})

    if ($ntlmV1 -gt 0) {
        Write-Host ""
        Write-Host "  WARNUNG: NTLMv1 ist kryptographisch gebrochen!" -ForegroundColor Red
        Write-Host "  Mandiant Rainbow Tables ermoeglichen sofortige Credential-Kompromittierung." -ForegroundColor Red
        Write-Host ""
        Write-Host "  NTLMv1 Quellen:" -ForegroundColor Red
        $v1Accounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
            $parts = $_.Key -split '\|'
            Write-Host "    $($parts[0].PadRight(25)) von $($parts[1].PadRight(20)) $($_.Value)x" -ForegroundColor Red
        }
    }

    return @{
        V1Count = $ntlmV1
        V2Count = $ntlmV2
        V1Accounts = $v1Accounts
    }
}

#endregion

function Export-ExcelReport {
    [CmdletBinding()]
    param(
        [hashtable]$Discovery,
        [hashtable]$Events,
        [PSCustomObject]$GPO,
        [string]$Path
    )

    $hasExcel = $false
    try {
        Import-Module ImportExcel -EA Stop
        $hasExcel = $true
    } catch {
        Write-Host "  ImportExcel-Modul nicht verfuegbar — nur CSV-Export" -ForegroundColor DarkGray
        Write-Host "  Installieren: Install-Module ImportExcel -Scope CurrentUser" -ForegroundColor DarkGray
    }

    $xlPath = Join-Path $Path "RC4_${domainShort}_Report.xlsx"

    if ($hasExcel) {
        # Standard conditional formatting rules
        $ctRC4 = @(
            (New-ConditionalText 'RC4_ONLY'    -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'RC4_AES'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            (New-ConditionalText 'DES_PRESENT' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'AES_ONLY'    -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
            (New-ConditionalText 'NOT_SET'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
        )

        # --- Overview Tab (first) ---
        $overviewData = @()
        $overviewData += [PSCustomObject]@{
            Bereich='Domaene'; Wert=$domainFQDN; Status='Info'
            Hinweis="Domain Functional Level: $((Get-ADDomain -EA SilentlyContinue).DomainMode)"
        }
        $overviewData += [PSCustomObject]@{
            Bereich='Server'; Wert=$env:COMPUTERNAME; Status='Info'; Hinweis="Audit-Host"
        }
        $overviewData += [PSCustomObject]@{
            Bereich='Zeitraum'; Wert="Letzte $Hours Stunden"; Status='Info'; Hinweis=(Get-Date -Format 'yyyy-MM-dd HH:mm')
        }
        $overviewData += [PSCustomObject]@{
            Bereich='Kerberos GPO'; Wert=$GPO.Value; Status=$(
                if ($GPO.HasDES) {'Fehler'} elseif ($GPO.HasRC4) {'Warnung'} else {'Information'}
            ); Hinweis=$GPO.Recommendation
        }

        # Category summaries
        foreach ($key in @('Citrix','Igel','NonWindows','Delegation')) {
            $items = @($Discovery[$key])
            $rc4Items = @($items | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
            $total = SafeCount $items
            $rc4Count = SafeCount $rc4Items
            $status = if ($rc4Count -gt 0) {'Warnung'} elseif ($total -gt 0) {'Information'} else {'Leer'}
            $overviewData += [PSCustomObject]@{
                Bereich=$key; Wert="$total gefunden, $rc4Count mit RC4/DES"
                Status=$status; Hinweis=''
            }
        }

        # Event summaries
        if ($Events) {
            $overviewData += [PSCustomObject]@{
                Bereich='RC4 Service Tickets'; Wert=(SafeCount $Events.RC4Tickets)
                Status=$(if ((SafeCount $Events.RC4Tickets) -gt 0) {'Fehler'} else {'Information'})
                Hinweis='Event 4769 mit EncType 0x17'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Pre-Auth Fehler'; Wert=(SafeCount $Events.PreAuthFails)
                Status=$(if ((SafeCount $Events.PreAuthFails) -gt 50) {'Warnung'} elseif ((SafeCount $Events.PreAuthFails) -gt 0) {'Info'} else {'Information'})
                Hinweis='Event 4771'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Failed Logons'; Wert=(SafeCount $Events.LogonFails)
                Status=$(if ((SafeCount $Events.LogonFails) -gt 100) {'Warnung'} elseif ((SafeCount $Events.LogonFails) -gt 0) {'Info'} else {'Information'})
                Hinweis='Event 4625'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Account Lockouts'; Wert=(SafeCount $Events.Lockouts)
                Status=$(if ((SafeCount $Events.Lockouts) -gt 10) {'Fehler'} elseif ((SafeCount $Events.Lockouts) -gt 0) {'Warnung'} else {'Information'})
                Hinweis='Event 4740'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Korrelierte Lockouts'; Wert=(SafeCount $Events.Correlated)
                Status=$(if ((SafeCount $Events.Correlated) -gt 0) {'Fehler'} else {'Information'})
                Hinweis='Kerberos-Fehler innerhalb 120s vor Lockout'
            }
        }

        $overviewData | Export-Excel -Path $xlPath -WorksheetName 'Uebersicht' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $(
            New-ConditionalText 'Fehler' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
            New-ConditionalText 'Warnung'  -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
            New-ConditionalText 'Information'       -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
        )

        # --- Data Tabs ---
        if ((SafeCount $Discovery.Citrix) -gt 0) {
            $Discovery.Citrix | Export-Excel -Path $xlPath -WorksheetName 'Citrix' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $ctRC4
        }
        if ((SafeCount $Discovery.Igel) -gt 0) {
            $Discovery.Igel | Export-Excel -Path $xlPath -WorksheetName 'Igel' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $ctRC4
        }
        if ((SafeCount $Discovery.NonWindows) -gt 0) {
            $Discovery.NonWindows | Export-Excel -Path $xlPath -WorksheetName 'NonWindows' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                $ctRC4 + @(New-ConditionalText 'Linux' -BackgroundColor '#E6F1FB' -ConditionalTextColor '#0C447C')
            )
        }
        if ((SafeCount $Discovery.Delegation) -gt 0) {
            $Discovery.Delegation | Export-Excel -Path $xlPath -WorksheetName 'Delegation' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                $ctRC4 + @(New-ConditionalText 'Unconstrained' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            )
        }

        @($GPO) | Export-Excel -Path $xlPath -WorksheetName 'GPO_Policy' -AutoSize -FreezeTopRow -BoldTopRow -Append

        # Event tabs
        if ($Events) {
            if ((SafeCount $Events.RC4Tickets) -gt 0) {
                $Events.RC4Tickets | Export-Excel -Path $xlPath -WorksheetName 'RC4_Tickets' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                    New-ConditionalText 'True' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
                    New-ConditionalText 'RC4' -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
                )
            }
            if ((SafeCount $Events.PreAuthFails) -gt 0) {
                $Events.PreAuthFails | Select-Object -First 500 | Export-Excel -Path $xlPath -WorksheetName 'PreAuth_Fehler' -AutoSize -FreezeTopRow -BoldTopRow -Append
            }
            if ((SafeCount $Events.Correlated) -gt 0) {
                $Events.Correlated | Export-Excel -Path $xlPath -WorksheetName 'Korrelation' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                    New-ConditionalText -Range 'F:F' -RuleType GreaterThan -ConditionValue 60 -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
                )
            }
            if ((SafeCount $Events.LogonFails) -gt 0) {
                $Events.LogonFails | Select-Object -First 500 | Export-Excel -Path $xlPath -WorksheetName 'LogonFails' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                    New-ConditionalText 'NTLM' -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
                    New-ConditionalText 'Kerberos' -BackgroundColor '#E6F1FB' -ConditionalTextColor '#0C447C'
                )
            }
            if ((SafeCount $Events.Lockouts) -gt 0) {
                $Events.Lockouts | Export-Excel -Path $xlPath -WorksheetName 'Lockouts' -AutoSize -FreezeTopRow -BoldTopRow -Append
            }
        }

        Write-Host "`n  Excel-Report : $xlPath" -ForegroundColor Green
    }

    # CSV fallback / additional
    $csvFiles = @()
    foreach ($key in @('Citrix','Igel','NonWindows','Delegation')) {
        if ((SafeCount $Discovery[$key]) -gt 0) {
            $p = Export-ToCsv $Discovery[$key] $key
            if ($p) { $csvFiles += $p; Write-Host "  CSV          : $p" -ForegroundColor Green }
        }
    }
    $p = Export-ToCsv @($GPO) 'GPO_Policy'
    if ($p) { $csvFiles += $p }

    if ($Events) {
        foreach ($key in @('RC4Tickets','PreAuthFails','LogonFails','Lockouts','Correlated')) {
            if ((SafeCount $Events[$key]) -gt 0) {
                $p = Export-ToCsv $Events[$key] $key
                if ($p) { $csvFiles += $p }
            }
        }
    }

    return @{ ExcelPath = $xlPath; CsvFiles = $csvFiles }
}

function Compress-Report {
    [CmdletBinding()]
    param([string]$FolderPath)
    $zipPath = "${FolderPath}.zip"
    try {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path "$FolderPath\*" -DestinationPath $zipPath -Force
        Write-Host "  ZIP          : $zipPath" -ForegroundColor Green
        return $zipPath
    } catch {
        Write-Host "  ZIP fehlgeschlagen: $_" -ForegroundColor Red
        return $null
    }
}

function Write-Kreuzpruefung {
    [CmdletBinding()]
    param(
        [hashtable]$Discovery,
        [hashtable]$Events,
        [PSCustomObject]$GPO,
        [array]$AllSystems,
        [array]$RC4Risk,
        [array]$DelegRC4
    )

    Write-Host "`n  --- KREUZPRUEFUNG ---" -ForegroundColor Magenta
    Write-Host "  Kombination der Befunde zu bedingten Risikobewertungen:`n" -ForegroundColor DarkGray

    $findings = @()
    $rc4TicketCount = if ($Events) { SafeCount $Events.RC4Tickets } else { 0 }
    $preAuthCount   = if ($Events) { SafeCount $Events.PreAuthFails } else { 0 }
    $lockoutCount   = if ($Events) { SafeCount $Events.Lockouts } else { 0 }
    $correlCount    = if ($Events) { SafeCount $Events.Correlated } else { 0 }
    $rc4RiskCount   = SafeCount $RC4Risk
    $delegRC4Count  = SafeCount $DelegRC4

    # ============================================================
    # 1. RC4 in Accounts vs. RC4 Tickets
    # ============================================================
    if ($rc4RiskCount -gt 0 -and $rc4TicketCount -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=1; Typ='Information'; Bereich='RC4 in Accounts'
            Befund="$rc4RiskCount Accounts haben RC4 im Attribut, aber der KDC stellt 0 RC4-Tickets aus."
            Bewertung="Passiv — der KDC waehlt bereits AES. Das Setzen auf Wert 24 (AES-only) formalisiert den Ist-Zustand und ist risikofrei."
            Bedingung="Wird erst aktiv wenn ein Server 2025 DC promoted wird (anderes KDC-Verhalten) oder Constrained Delegation unter Last RC4 aushandelt."
        }
        Write-Host "  [1] PASSIV: RC4 in $rc4RiskCount Accounts" -ForegroundColor Green
        Write-Host "      Der KDC stellt 0 RC4-Tickets aus — AES wird bereits verwendet." -ForegroundColor DarkGray
        Write-Host "      Accounts auf Wert 24 setzen formalisiert den Ist-Zustand." -ForegroundColor DarkGray
        Write-Host "      -> Wird aktiv wenn: Server 2025 DC oder KCD unter Last`n" -ForegroundColor DarkGray
    }
    elseif ($rc4RiskCount -gt 0 -and $rc4TicketCount -gt 0) {
        $findings += [PSCustomObject]@{
            Nr=1; Typ='Fehler'; Bereich='RC4 Tickets'
            Befund="$rc4TicketCount RC4-Tickets in den letzten $Hours Stunden. $rc4RiskCount Accounts mit RC4 im Attribut."
            Bewertung="Aktiv — der KDC stellt RC4-Tickets aus. Ein Server 2025 System wuerde diese ablehnen."
            Bedingung="Sofort betroffen bei: Server 2025 DC, Exchange SE Go-Live, oder April-2026-Update."
        }
        Write-Host "  [1] AKTIV: $rc4TicketCount RC4-Tickets fliessen!" -ForegroundColor Red
        Write-Host "      Der KDC stellt aktiv RC4 aus. Accounts auf Wert 24 setzen + PW rotieren." -ForegroundColor Red
        Write-Host "      -> Betroffen: Server 2025, Exchange SE Go-Live, April-2026-Update`n" -ForegroundColor Red
    }
    elseif ($rc4RiskCount -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=1; Typ='Information'; Bereich='RC4 in Accounts'
            Befund="Keine Accounts mit RC4/DES gefunden. 0 RC4-Tickets."
            Bewertung="Kein RC4-Risiko. Umgebung ist bereit fuer Server 2025 und das April-2026-Update."
            Bedingung="Keine."
        }
        Write-Host "  [1] OK: Keine RC4/DES Accounts, keine RC4-Tickets`n" -ForegroundColor Green
    }

    # ============================================================
    # 2. GPO vs. Account-Realitaet
    # ============================================================
    if ($GPO.HasDES -and $rc4TicketCount -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=2; Typ='Warnung'; Bereich='GPO erlaubt DES'
            Befund="GPO erlaubt DES (Wert $($GPO.Value)), aber es fliessen 0 DES/RC4-Tickets."
            Bewertung="Schlafend — kein aktives Problem. Die GPO haelt aber die Tuer fuer DES offen."
            Bedingung="Wird aktiv wenn ein sehr alter Client oder eine Appliance mit DES-only ins Netz kommt, oder wenn ein Angreifer per Kerberoasting gezielt DES erzwingt."
        }
        Write-Host "  [2] SCHLAFEND: GPO erlaubt DES (Wert $($GPO.Value))" -ForegroundColor Yellow
        Write-Host "      Aktuell 0 DES-Tickets — aber DES ist offen fuer Kerberoasting-Angriffe." -ForegroundColor DarkGray
        Write-Host "      GPO auf 2147483644 (DES entfernen) ist risikofrei da 0 DES-Traffic." -ForegroundColor DarkGray
        Write-Host "      -> Wird aktiv bei: alter Client/Appliance mit DES-only, oder Angriff`n" -ForegroundColor DarkGray
    }
    elseif ($GPO.HasRC4 -and -not $GPO.HasDES -and $rc4TicketCount -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=2; Typ='Warnung'; Bereich='GPO erlaubt RC4'
            Befund="GPO erlaubt RC4+AES (kein DES), 0 RC4-Tickets."
            Bewertung="Akzeptabler Uebergangszustand. RC4 in der GPO ist das Sicherheitsnetz waehrend Accounts auf 24 umgestellt werden."
            Bedingung="GPO auf 2147483640 (AES-only) erst setzen wenn alle Accounts auf Wert 24 und Kennwoerter rotiert."
        }
        Write-Host "  [2] UEBERGANG: GPO erlaubt RC4 aber 0 RC4-Tickets" -ForegroundColor Green
        Write-Host "      Akzeptabel. GPO auf AES-only erst nach vollstaendiger Account-Bereinigung.`n" -ForegroundColor DarkGray
    }
    elseif ($null -eq $GPO.Value -or $GPO.Value -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=2; Typ='Warnung'; Bereich='GPO nicht gesetzt'
            Befund="GPO nicht konfiguriert — folgt OS-Default."
            Bewertung="Schlafend — aktuell kein Problem. Ab April 2026 (CVE-2026-20833) wird der Default auf AES-only geaendert."
            Bedingung="Wird automatisch aktiv am Patchday April 2026. Alle Accounts mit Wert 0 (NOT SET) werden dann als AES-only behandelt."
        }
        Write-Host "  [2] SCHLAFEND: GPO nicht gesetzt — folgt OS-Default" -ForegroundColor Yellow
        Write-Host "      Ab April 2026 aendert sich der Default automatisch auf AES-only." -ForegroundColor DarkGray
        Write-Host "      -> Wird aktiv am: Patchday April 2026 (CVE-2026-20833)`n" -ForegroundColor DarkGray
    }

    # ============================================================
    # 3. Delegation + RC4 vs. Tickets
    # ============================================================
    if ($delegRC4Count -gt 0 -and $rc4TicketCount -eq 0) {
        $delegNames = ($DelegRC4 | Select-Object -First 3 -ExpandProperty Name) -join ', '
        $findings += [PSCustomObject]@{
            Nr=3; Typ='Warnung'; Bereich='Delegation mit RC4'
            Befund="$delegRC4Count Delegation-Accounts mit RC4 ($delegNames), aber 0 RC4-Tickets."
            Bewertung="Schlafend — Constrained Delegation verwendet unter normaler Last AES. Unter hoher Last oder bei bestimmten S4U2Proxy-Konstellationen kann der KDC RC4 fuer das delegierte Ticket waehlen."
            Bedingung="Wird aktiv bei: hoher Delegations-Last (z.B. Exchange SE Go-Live mit hunderten OWA-Sessions/Minute ueber Kemp), oder wenn der Backend-Account ebenfalls RC4 im Attribut hat."
        }
        Write-Host "  [3] SCHLAFEND: $delegRC4Count Delegation-Accounts mit RC4 ($delegNames)" -ForegroundColor Yellow
        Write-Host "      Aktuell 0 RC4-Tickets — KCD handelt AES aus." -ForegroundColor DarkGray
        Write-Host "      -> Wird aktiv bei: hoher Delegations-Last (Go-Live), S4U2Proxy Edge Cases`n" -ForegroundColor DarkGray
    }
    elseif ($delegRC4Count -gt 0 -and $rc4TicketCount -gt 0) {
        $findings += [PSCustomObject]@{
            Nr=3; Typ='Fehler'; Bereich='Delegation mit RC4'
            Befund="$delegRC4Count Delegation-Accounts mit RC4 UND $rc4TicketCount RC4-Tickets."
            Bewertung="Aktiv — Delegation-Accounts muessen sofort auf AES-only gesetzt werden. Keytabs mit AES neu erstellen."
            Bedingung="Betrifft alle Dienste hinter dem LoadBalancer/Proxy."
        }
        Write-Host "  [3] AKTIV: Delegation mit RC4 UND RC4-Tickets!" -ForegroundColor Red
        Write-Host "      Delegation-Accounts sofort auf 24 + Keytabs mit AES neu erstellen.`n" -ForegroundColor Red
    }

    # ============================================================
    # 4. PreAuth Failures vs. RC4
    # ============================================================
    if ($preAuthCount -gt 50 -and $rc4TicketCount -eq 0 -and $correlCount -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=4; Typ='Information'; Bereich='PreAuth Fehler'
            Befund="$preAuthCount Pre-Auth Fehler, aber 0 RC4-Tickets und 0 korrelierte Lockouts."
            Bewertung="Getrennt vom RC4-Thema — die Fehler sind Credential-Hygiene (falsche Passwoerter, abgelaufene Accounts). Kein Kerberos-Encryption-Problem."
            Bedingung="Wird RC4-relevant wenn: nach April-2026-Update die Fallback-Kette (Kerberos->NTLM) haeufiger getriggert wird und die falschen Credentials dann zu Lockouts fuehren."
        }
        Write-Host "  [4] GETRENNT: $preAuthCount PreAuth-Fehler sind kein RC4-Problem" -ForegroundColor Green
        Write-Host "      0 RC4-Tickets, 0 korrelierte Lockouts. Ursache: Credential-Hygiene." -ForegroundColor DarkGray
        Write-Host "      -> Wird RC4-relevant wenn: April-2026-Update die Fallback-Kette verschaerft`n" -ForegroundColor DarkGray
    }
    elseif ($preAuthCount -gt 50 -and $correlCount -gt 0) {
        $findings += [PSCustomObject]@{
            Nr=4; Typ='Fehler'; Bereich='Fallback-Kette'
            Befund="$preAuthCount Pre-Auth Fehler mit $correlCount korrelierten Lockouts."
            Bewertung="Aktiv — Kerberos-Fehler loesen NTLM-Fallback aus, der zu Kontosperrungen fuehrt. Die betroffenen Accounts haben gespeicherte alte Credentials."
            Bedingung="Verschlechtert sich mit Server 2025 DC (mehr Kerberos-Fehler durch RC4-Ablehnung) und nach April-2026-Update."
        }
        Write-Host "  [4] AKTIV: $correlCount Lockouts durch Kerberos-Fallback-Kette!" -ForegroundColor Red
        Write-Host "      Kerberos scheitert -> NTLM -> altes Passwort -> Lockout." -ForegroundColor Red
        Write-Host "      -> Verschlechtert sich mit: Server 2025 DC, April-2026-Update`n" -ForegroundColor Red
    }

    # ============================================================
    # 5. SMB Signing (aus GPO / bekannter Zustand)
    # ============================================================
    # Hinweis: SMB-Daten kommen aus Check-Server2025Defaults, nicht aus diesem Skript.
    # Wir koennen aber den Hinweis geben.
    $findings += [PSCustomObject]@{
        Nr=5; Typ='Information'; Bereich='SMB Signing'
        Befund="SMB Signing wird von diesem Skript nicht geprueft."
        Bewertung="SMB Signing Mismatch ist ein separates Risiko bei Server 2025 Einfuehrung. Pruefen mit Check-Server2025Defaults-v4.ps1."
        Bedingung="Wenn alle Server konsistent True/True haben: kein Risiko. Wenn gemischt: Drucker und Appliances pruefen."
    }
    Write-Host "  [5] HINWEIS: SMB Signing nicht in diesem Skript" -ForegroundColor DarkGray
    Write-Host "      Separat pruefen mit Check-Server2025Defaults-v4.ps1`n" -ForegroundColor DarkGray

    # ============================================================
    # 6. SAP-Indikation
    # ============================================================
    if ($rc4TicketCount -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=6; Typ='Information'; Bereich='SAP Kerberos'
            Befund="0 RC4-Tickets — SAP erhaelt und akzeptiert AES-Tickets."
            Bewertung="Hinweis — wenn SAP heute mit AES funktioniert, funktioniert es auch nach DC-Account-Umstellung auf Wert 24, Server 2025 DC, und April-2026-Update."
            Bedingung="Keine weitere Aktion noetig solange der SAP Kernel nicht downgraded wird."
        }
        Write-Host "  [6] HINWEIS: SAP" -ForegroundColor Green
        Write-Host "      0 RC4-Tickets — SAP funktioniert mit AES. Kein RC4-Risiko fuer SAP." -ForegroundColor DarkGray
        Write-Host "      -> Bleibt mitigiert solange SAP Kernel nicht downgraded wird`n" -ForegroundColor DarkGray
    }

    # ============================================================
    # 7. Maschinen-Account Passwort-Rotation
    # ============================================================
    $machineAccts = @()
    if ($Events -and $Events.PreAuthFails) {
        $machineAccts = @($Events.PreAuthFails | Where-Object { $_.Account -match '\$$' -and $_.Status -eq '0x18' } | Select-Object -ExpandProperty Account -Unique)
    }
    if ($machineAccts.Count -gt 0) {
        $machineList = ($machineAccts | Select-Object -First 3) -join ', '
        $findings += [PSCustomObject]@{
            Nr=7; Typ='Warnung'; Bereich='Maschinenkennwort'
            Befund="$($machineAccts.Count) Maschinen-Accounts mit Pre-Auth Fehlern ($machineList)."
            Bewertung="Schlafend — Kennwort-Rotation funktioniert nicht sauber. Bei einem Server 2025 DC generiert die Rotation nur AES-Keys, aeltere DCs erwarten RC4-Keys."
            Bedingung="Wird aktiv ca. 30 Tage nach Server 2025 DC Promotion. Server fallen einzeln aus, ueber Tage verteilt."
        }
        Write-Host "  [7] SCHLAFEND: $($machineAccts.Count) Maschinen-Accounts mit PreAuth-Fehler" -ForegroundColor Yellow
        Write-Host "      $machineList" -ForegroundColor Yellow
        Write-Host "      Kennwort-Rotation nicht sauber. Bei 2025 DC: AES-only Keys → Ausfall." -ForegroundColor DarkGray
        Write-Host "      -> Wird aktiv: ~30 Tage nach Server 2025 DC Promotion`n" -ForegroundColor DarkGray
    }

    # ============================================================
    # 8. NOT SET Accounts (Wert 0) vs. April-Update
    # ============================================================
    $notSetCount = ($AllSystems | Where-Object { $_.EncCategory -eq 'NOT_SET' } | Measure-Object).Count
    if ($notSetCount -gt 0) {
        $findings += [PSCustomObject]@{
            Nr=8; Typ='Warnung'; Bereich='NOT SET Accounts'
            Befund="$notSetCount Accounts mit Wert 0 (NOT SET) — folgen dem Domain-Default."
            Bewertung="Schlafend — aktuell erlaubt der Default RC4+AES. Ab April 2026 wird der Default auf AES-only geaendert."
            Bedingung="Wird automatisch aktiv am Patchday April 2026. Wenn diese Accounts RC4-Clients bedienen, schlagen deren Authentifizierungen fehl."
        }
        Write-Host "  [8] SCHLAFEND: $notSetCount Accounts mit Wert 0 (NOT SET)" -ForegroundColor Yellow
        Write-Host "      Folgen dem Domain-Default. Ab April 2026: Default = AES-only." -ForegroundColor DarkGray
        Write-Host "      -> Wird aktiv am: Patchday April 2026 (automatisch)`n" -ForegroundColor DarkGray
    }

    # ============================================================
    # Zusammenfassung
    # ============================================================
    $aktiv     = @($findings | Where-Object { $_.Typ -eq 'Fehler' })
    $schlafend = @($findings | Where-Object { $_.Typ -eq 'Warnung' })
    $passiv    = @($findings | Where-Object { $_.Typ -match 'PASSIV|MITIGIERT|GETRENNT|UEBERGANG' })

    Write-Host "  --- ZUSAMMENFASSUNG KREUZPRUEFUNG ---" -ForegroundColor Magenta
    Write-Host "  Aktive Risiken  : $($aktiv.Count)" -ForegroundColor $(if ($aktiv.Count -gt 0) {'Red'} else {'Green'})
    Write-Host "  Schlafende      : $($schlafend.Count)" -ForegroundColor $(if ($schlafend.Count -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  Passiv/Mitigiert: $($passiv.Count)" -ForegroundColor Green
    Write-Host ""

    return $findings
}

function Send-Report {
    [CmdletBinding()]
    param(
        [string]$ZipPath,
        [string]$To,
        [string]$From,
        [string]$Smtp,
        [string]$Subject = "RC4 Discovery Report — $(Get-Date -Format 'yyyy-MM-dd')"
    )
    if (-not $ZipPath -or -not (Test-Path $ZipPath)) {
        Write-Host "  E-Mail: ZIP nicht vorhanden" -ForegroundColor Red; return
    }
    try {
        Send-MailMessage -To $To -From $From -Subject $Subject `
            -Body "RC4 Environment Discovery Report im Anhang. Erstellt am $(Get-Date -Format 'yyyy-MM-dd HH:mm')." `
            -Attachments $ZipPath -SmtpServer $Smtp -Encoding UTF8
        Write-Host "  E-Mail gesendet an: $To" -ForegroundColor Green
    } catch {
        Write-Host "  E-Mail fehlgeschlagen: $_" -ForegroundColor Red
    }
}

function Normalize-TypLabel {
    <#
    .SYNOPSIS
        Normalisiert alte Typ-Labels zu Event-Log-Levels.
        Aeltere CSVs enthalten SCHLAFEND/PASSIV/AKTIV — neue verwenden Fehler/Warnung/Information.
    #>
    param([string]$Typ)
    switch ($Typ) {
        'AKTIV'              { 'Fehler' }
        'KRITISCH'           { 'Fehler' }
        'SCHLAFEND'          { 'Warnung' }
        'UEBERGANG'          { 'Warnung' }
        'PRUEFEN'            { 'Warnung' }
        'PASSIV'             { 'Information' }
        'IMPLIZIT MITIGIERT' { 'Information' }
        'OHNE FOLGEN'        { 'Information' }
        'OHNE_FOLGEN'        { 'Information' }
        'GETRENNT'           { 'Information' }
        'HINWEIS'            { 'Information' }
        'OK'                 { 'Information' }
        'Fehler'             { 'Fehler' }
        'Warnung'            { 'Warnung' }
        'Information'        { 'Information' }
        default              { $Typ }
    }
}

function Import-PreviousReport {
    [CmdletBinding()]
    param([string]$Path)

    Write-Host "`n=== IMPORT AUS VORHERIGEM REPORT ===" -ForegroundColor Cyan
    Write-Host "  Quelle: $Path" -ForegroundColor White

    if (-not (Test-Path $Path)) {
        Write-Host "  FEHLER: Pfad nicht gefunden: $Path" -ForegroundColor Red
        return $null
    }

    $imported = @{
        Discovery = @{ Citrix=@(); Igel=@(); NonWindows=@(); Delegation=@() }
        Events    = @{ RC4Tickets=@(); PreAuthFails=@(); LogonFails=@(); Lockouts=@(); Correlated=@() }
        GPO       = $null
    }

    # CSV-Dateien laden
    $csvMap = @{
        'Citrix'       = @{ Target='Discovery'; Key='Citrix' }
        'Igel'         = @{ Target='Discovery'; Key='Igel' }
        'NonWindows'   = @{ Target='Discovery'; Key='NonWindows' }
        'Delegation'   = @{ Target='Discovery'; Key='Delegation' }
        'GPO_Policy'   = @{ Target='GPO';       Key=$null }
        'RC4Tickets'   = @{ Target='Events';    Key='RC4Tickets' }
        'PreAuthFails' = @{ Target='Events';    Key='PreAuthFails' }
        'LogonFails'   = @{ Target='Events';    Key='LogonFails' }
        'Lockouts'     = @{ Target='Events';    Key='Lockouts' }
        'Correlated'   = @{ Target='Events';    Key='Correlated' }
    }

    $loadedFiles = 0
    foreach ($name in $csvMap.Keys) {
        $csvPath = Join-Path $Path "${name}.csv"
        if (-not (Test-Path $csvPath)) { continue }

        try {
            $data = @(Import-Csv $csvPath -Delimiter ';' -Encoding UTF8)
            $map = $csvMap[$name]

            if ($map.Target -eq 'GPO') {
                # GPO needs reconstruction as object with typed properties
                $row = $data | Select-Object -First 1
                $imported.GPO = [PSCustomObject]@{
                    Server         = $row.Server
                    Value          = if ($row.Value -and $row.Value -ne '') { [int]$row.Value } else { $null }
                    HasDES         = $row.HasDES -eq 'True'
                    HasRC4         = $row.HasRC4 -eq 'True'
                    HasAES128      = $row.HasAES128 -eq 'True'
                    HasAES256      = $row.HasAES256 -eq 'True'
                    Recommendation = $row.Recommendation
                    Bewertung      = $row.Bewertung
                }
            }
            elseif ($map.Target -eq 'Discovery') {
                $imported.Discovery[$map.Key] = $data
            }
            elseif ($map.Target -eq 'Events') {
                $imported.Events[$map.Key] = $data
            }

            $loadedFiles++
            Write-Status "  $name" "$($data.Count) Eintraege" 'Green'
        }
        catch {
            Write-Host "  $name.csv: Fehler beim Import — $_" -ForegroundColor Red
        }
    }

    # GPO Fallback wenn keine CSV
    if (-not $imported.GPO) {
        Write-Host "  GPO_Policy.csv nicht gefunden — lese GPO live vom lokalen System" -ForegroundColor Yellow
        $imported.GPO = Get-KerberosGPOPolicy
    }

    Write-Host "  $loadedFiles CSV-Dateien geladen" -ForegroundColor Cyan

    if ($loadedFiles -eq 0) {
        Write-Host "  FEHLER: Keine CSVs gefunden in $Path" -ForegroundColor Red
        return $null
    }

    return $imported
}

#endregion
#endregion

#region ============ READINESS-FUNKTIONEN (ehem. Check-Server2025Defaults-v4) ============
#region --- AD Discovery Core ---

function Get-DomainDN {
    try { return (Get-ADDomain -EA Stop).DistinguishedName }
    catch {
        try { return ([ADSI]"LDAP://RootDSE").defaultNamingContext.ToString() }
        catch { throw "Cannot determine domain DN." }
    }
}

function Get-ConfigDN {
    param([string]$DomainDN)
    try { return ([ADSI]"LDAP://RootDSE").configurationNamingContext.ToString() }
    catch { return "CN=Configuration,$DomainDN" }
}

function Search-AD {
    [CmdletBinding()]
    param(
        [string]$SearchBase, [string]$LdapFilter,
        [string[]]$Properties = @('name','distinguishedName'),
        [ValidateSet('Base','OneLevel','Subtree')][string]$SearchScope = 'Subtree'
    )
    try {
        Get-Command Get-ADObject -EA Stop | Out-Null
        return Get-ADObject -SearchBase $SearchBase -LDAPFilter $LdapFilter `
            -Properties $Properties -SearchScope $SearchScope -EA Stop
    } catch { }
    # ADSI fallback
    try {
        $root = [ADSI]"LDAP://$SearchBase"
        $s = New-Object System.DirectoryServices.DirectorySearcher($root)
        $s.Filter = $LdapFilter; $s.SearchScope = $SearchScope; $s.PageSize = 1000
        foreach ($p in $Properties) { [void]$s.PropertiesToLoad.Add($p.ToLower()) }
        $r = $s.FindAll()
        $out = foreach ($e in $r) {
            $o = [PSCustomObject]@{ DistinguishedName=$e.Properties['distinguishedname'][0]; Name=$e.Properties['name'][0] }
            foreach ($p in $Properties) {
                $l = $p.ToLower()
                if ($l -notin @('name','distinguishedname')) {
                    $v = $e.Properties[$l]
                    $o | Add-Member -NotePropertyName $p -NotePropertyValue $(if ($v -and $v.Count -gt 0) { $v[0] } else { $null }) -Force
                }
            }
            $o
        }
        $r.Dispose(); return $out
    } catch { return @() }
}

function Resolve-Computer {
    param([string]$DomainDN, [string]$Name)
    $c = Search-AD -SearchBase $DomainDN -LdapFilter "(&(objectClass=computer)(cn=$Name))" `
        -Properties @('name','dNSHostName','operatingSystem')
    if ($c) { return @{ Name=$c.Name; HostName=$(if($c.dNSHostName){$c.dNSHostName}else{$c.Name}); OS=$c.operatingSystem } }
    return @{ Name=$Name; HostName=$Name; OS=$null }
}

#endregion

#region --- Inventory Management ---

$script:serverInventory = @{}

function Add-ToInventory {
    param([string]$Name, [string]$HostName, [string]$OS, [string]$Role, [string]$Source)
    $key = $Name.ToUpper()
    if (-not $script:serverInventory.ContainsKey($key)) {
        $script:serverInventory[$key] = @{
            Name=$Name; HostName=$(if($HostName){$HostName}else{$Name}); OS=$OS
            Roles=[System.Collections.Generic.List[string]]::new()
            Sources=[System.Collections.Generic.List[string]]::new()
        }
    }
    $inv = $script:serverInventory[$key]
    if ($Role -notin $inv.Roles) { $inv.Roles.Add($Role) }
    if ($Source -notin $inv.Sources) { $inv.Sources.Add($Source) }
    if (-not $inv.OS -and $OS) { $inv.OS = $OS }
    if ((-not $inv.HostName -or $inv.HostName -eq $Name) -and $HostName) { $inv.HostName = $HostName }
}

#endregion

#region --- Phase 1: Role Discovery ---

function Find-DomainControllers {
    param([string]$DomainDN, [string]$ConfigDN)
    $sites = "CN=Sites,$ConfigDN"
    $ntdsa = Search-AD -SearchBase $sites -LdapFilter '(objectClass=nTDSDSA)' -Properties @('distinguishedName')
    $count = 0
    foreach ($n in $ntdsa) {
        $serverDN = ($n.DistinguishedName -split ',', 2)[1]
        $srvName = ($serverDN -split ',')[0] -replace '^CN=',''
        $comp = Resolve-Computer -DomainDN $DomainDN -Name $srvName
        Add-ToInventory -Name $comp.Name -HostName $comp.HostName -OS $comp.OS -Role 'DC' -Source 'nTDSDSA'
        $count++
    }
    return $count
}

function Find-ExchangeServers {
    param([string]$DomainDN, [string]$ConfigDN)
    $services = "CN=Services,$ConfigDN"
    $exchPath = "CN=Microsoft Exchange,$services"
    $count = 0
    try {
        $exchSrv = Search-AD -SearchBase $exchPath -LdapFilter '(objectClass=msExchExchangeServer)' -Properties @('name')
        foreach ($ex in $exchSrv) {
            $comp = Resolve-Computer -DomainDN $DomainDN -Name $ex.Name
            Add-ToInventory -Name $comp.Name -HostName $comp.HostName -OS $comp.OS -Role 'Exchange' -Source 'msExchExchangeServer'
            $count++
        }
    } catch { }
    # DAG
    try {
        $dags = Search-AD -SearchBase $exchPath -LdapFilter '(objectClass=msExchMDBAvailabilityGroup)' `
            -Properties @('name','msExchMDBAvailabilityGroupMemberLink')
        foreach ($dag in $dags) {
            $links = $dag.msExchMDBAvailabilityGroupMemberLink
            if ($links) {
                $la = if ($links -is [string]) { @($links) } else { @($links) }
                foreach ($link in $la) {
                    $mn = ($link -split ',')[0] -replace '^CN=',''
                    $key = $mn.ToUpper()
                    if ($script:serverInventory.ContainsKey($key)) {
                        if ('ExchangeDAG' -notin $script:serverInventory[$key].Roles) {
                            $script:serverInventory[$key].Roles.Add('ExchangeDAG')
                        }
                    } else {
                        $comp = Resolve-Computer -DomainDN $DomainDN -Name $mn
                        Add-ToInventory -Name $comp.Name -HostName $comp.HostName -OS $comp.OS -Role 'Exchange' -Source 'DAG'
                        Add-ToInventory -Name $comp.Name -HostName $comp.HostName -OS $comp.OS -Role 'ExchangeDAG' -Source 'DAG'
                        $count++
                    }
                }
            }
        }
    } catch { }
    return $count
}

function Find-CertificateAuthorities {
    param([string]$DomainDN, [string]$ConfigDN)
    $pkiPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDN"
    $count = 0
    try {
        $cas = Search-AD -SearchBase $pkiPath -LdapFilter '(objectClass=pKIEnrollmentService)' `
            -Properties @('name','dNSHostName','distinguishedName')
        foreach ($ca in $cas) {
            $caDisplayName = $ca.Name  # z.B. "Issuing Certificate Authority"
            $hn = $ca.dNSHostName
            # Extract actual server name from dNSHostName or fall back to searching AD
            $serverName = $null
            if ($hn) {
                $serverName = ($hn -split '\.')[0]  # FQDN -> short name
            }
            if (-not $serverName) {
                # Try to find hosting server via computer search
                $comp = Resolve-Computer -DomainDN $DomainDN -Name $caDisplayName
                if ($comp.OS) {
                    $serverName = $comp.Name
                    $hn = $comp.HostName
                }
            }
            # Use server name for inventory, store CA name as source detail
            $invName = if ($serverName) { $serverName } else { $caDisplayName }
            $invHost = if ($hn) { $hn } else { $invName }
            Add-ToInventory -Name $invName -HostName $invHost -OS $null -Role 'CA' -Source "pKIEnrollmentService ($caDisplayName)"
            $count++
        }
    } catch { }
    return $count
}

function Find-ClusterNodes {
    param([string]$DomainDN)
    $count = 0
    $dagNames = @{}

    # Pre-collect known DAG names from Exchange discovery (if already in inventory)
    foreach ($key in $script:serverInventory.Keys) {
        $inv = $script:serverInventory[$key]
        if ('ExchangeDAG' -in $inv.Roles -or 'Exchange' -in $inv.Roles) {
            $dagNames[$key] = $true
        }
    }

    # CNOs: MSClusterVirtualServer SPNs - these are VIRTUAL names, not physical servers
    try {
        $cno = Search-AD -SearchBase $DomainDN -LdapFilter '(&(objectClass=computer)(servicePrincipalName=MSClusterVirtualServer/*))' `
            -Properties @('name','dNSHostName','operatingSystem','servicePrincipalName')
        foreach ($c in $cno) {
            $cName = $c.Name.ToUpper()
            # Check if this CNO is a DAG virtual name
            if ($dagNames.ContainsKey($cName) -or $c.Name -match 'DAG|EXCHDAG') {
                # This is a DAG cluster object — tag it properly
                Add-ToInventory -Name $c.Name -HostName $c.dNSHostName -OS $c.operatingSystem `
                    -Role 'ExchangeDAG' -Source 'DAG CNO (MSClusterVirtualServer SPN)'
            } else {
                # Regular cluster virtual name (SQL, File, etc.)
                Add-ToInventory -Name $c.Name -HostName $c.dNSHostName -OS $c.operatingSystem `
                    -Role 'ClusterVNO' -Source 'CNO SPN (virtual name, not a physical server)'
            }
            $count++
        }
    } catch { }

    # Member nodes: MSServerCluster SPNs - these ARE physical servers
    try {
        $nodes = Search-AD -SearchBase $DomainDN -LdapFilter '(&(objectClass=computer)(servicePrincipalName=MSServerCluster/*))' `
            -Properties @('name','dNSHostName','operatingSystem')
        foreach ($n in $nodes) {
            Add-ToInventory -Name $n.Name -HostName $n.dNSHostName -OS $n.operatingSystem -Role 'Cluster' -Source 'Cluster Member SPN'
            $count++
        }
    } catch { }
    return $count
}

function Find-DFSServers {
    param([string]$DomainDN)
    $dfsPath = "CN=DFSR-GlobalSettings,CN=System,$DomainDN"
    $count = 0; $seen = @{}
    try {
        $members = Search-AD -SearchBase $dfsPath -LdapFilter '(objectClass=msDFSR-Member)' -Properties @('name','msDFSR-ComputerReference')
        foreach ($m in $members) {
            $ref = $m.'msDFSR-ComputerReference'
            if ($ref) {
                $cn = ($ref -split ',')[0] -replace '^CN=',''
                if (-not $seen.ContainsKey($cn)) {
                    $seen[$cn] = $true
                    $comp = Resolve-Computer -DomainDN $DomainDN -Name $cn
                    Add-ToInventory -Name $comp.Name -HostName $comp.HostName -OS $comp.OS -Role 'DFS' -Source 'msDFSR-Member'
                    $count++
                }
            }
        }
    } catch { }
    return $count
}

function Find-HyperVServers {
    param([string]$DomainDN)
    $count = 0
    try {
        $hvs = Search-AD -SearchBase $DomainDN `
            -LdapFilter '(&(objectClass=computer)(servicePrincipalName=Microsoft Virtual System Migration Service/*))' `
            -Properties @('name','dNSHostName','operatingSystem')
        foreach ($h in $hvs) {
            Add-ToInventory -Name $h.Name -HostName $h.dNSHostName -OS $h.operatingSystem -Role 'HyperV' -Source 'Hyper-V SPN'
            $count++
        }
    } catch { }
    return $count
}

# Alle aktivierten Server-OS-Computerkonten der Domaene (fuer -Scope AllServers).
# Ergaenzt die Rollen-Discovery: Systeme ohne erkannte Rolle kommen als 'Server'
# in die Inventur — Phase 2 prueft dann SMB/Kerberos auf JEDEM Server, nicht nur
# auf DC/Exchange/CA/Cluster/DFS/HyperV. Bereits entdeckte Rollen bleiben unberuehrt.
function Find-AllDomainServers {
    param([string]$DomainDN)
    $added = 0; $total = 0
    try {
        $all = Search-AD -SearchBase $DomainDN `
            -LdapFilter '(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties @('name','dNSHostName','operatingSystem')
        foreach ($c in $all) {
            $total++
            $key = ([string]$c.Name).ToUpper()
            if (-not $script:serverInventory.ContainsKey($key)) {
                Add-ToInventory -Name $c.Name -HostName $c.dNSHostName -OS $c.operatingSystem -Role 'Server' -Source 'AD-OS'
                $added++
            }
        }
    } catch { }
    return @{ Total = $total; Added = $added }
}

#endregion

# --- Boot-Fenster-Erkennung (Rausch-Filter) ---
# Ein Reboot erzeugt systematisch Eintraege die KEIN Befund sind: Dienste starten
# neu und authentifizieren sich, gecachte Credentials laufen an, Wininit schreibt
# Boot-Eintraege. Diese Events werden markiert und aus den Problemzaehlern
# herausgehalten — aber immer ausgewiesen, nie stumm unterdrueckt.
# LastBootUpTime allein reicht nicht: es kennt nur den letzten Start. Updates mit
# Doppel-Neustart (z.B. Secure-Boot-Zertifikat) erzeugen zwei Fenster, daher
# zusaetzlich Event 6005 (Eventlog-Dienst gestartet) aus dem Analysefenster.
function Get-BootWindows {
    param([long]$MsBack, [int]$PostRollMinutes = 5, [int]$PreRollMinutes = 2)
    $boots = New-Object System.Collections.Generic.List[datetime]
    try {
        $lb = (Get-CimInstance Win32_OperatingSystem -EA Stop).LastBootUpTime
        if ($lb) { [void]$boots.Add([datetime]$lb) }
    } catch {}
    $xmlBoot = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[(EventID=6005) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $MsBack)
    try {
        foreach ($e in @(Get-WinEvent -FilterXml $xmlBoot -MaxEvents 50 -EA Stop)) {
            if ($e.TimeCreated) { [void]$boots.Add([datetime]$e.TimeCreated) }
        }
    } catch {}

    $windows = New-Object System.Collections.Generic.List[PSObject]
    foreach ($b in @($boots | Sort-Object)) {
        # 60s-Schwelle: fasst denselben Start aus zwei Quellen zusammen (CIM
        # LastBootUpTime vs. Event 6005 liegen wenige Sekunden auseinander),
        # trennt aber echte Doppel-Neustarts (Secure-Boot-Update: ~2 min Abstand).
        # Lieber ein Fenster zu viel als eines zu kurz — ueberlappende Fenster
        # sind harmlos, ein verschmolzenes verliert Abdeckung.
        $dup = $false
        foreach ($w in $windows) {
            if ([math]::Abs(($b - $w.BootTime).TotalSeconds) -le 60) { $dup = $true; break }
        }
        if ($dup) { continue }
        [void]$windows.Add([PSCustomObject]@{
            BootTime = $b
            Start    = $b.AddMinutes(-1 * $PreRollMinutes)
            End      = $b.AddMinutes($PostRollMinutes)
        })
    }
    return ,$windows
}

function Test-BootWindow {
    param($Time, $Windows)
    if ($null -eq $Time) { return $false }
    $list = @($Windows)
    if ($list.Count -eq 0) { return $false }
    $t = $null
    try { $t = [datetime]$Time } catch { return $false }
    foreach ($w in $list) { if ($t -ge $w.Start -and $t -le $w.End) { return $true } }
    return $false
}

#region --- Phase 1.5: Kerberos Encryption Audit (AD-only) ---

function Get-KerberosEncryptionAudit {
    <#
    .SYNOPSIS
        Audits msDS-SupportedEncryptionTypes on computer accounts, service accounts,
        gMSAs, and trust objects to find RC4-only or missing AES keys.
        Server 2025 DCs no longer issue RC4 TGTs - these accounts will break.

    .DESCRIPTION
        Bitmask values for msDS-SupportedEncryptionTypes:
        0x1  = DES_CBC_CRC          (1)
        0x2  = DES_CBC_MD5          (2)
        0x4  = RC4_HMAC             (4)
        0x8  = AES128_CTS_HMAC_SHA1 (8)
        0x10 = AES256_CTS_HMAC_SHA1 (16)

        Common combinations:
        0    = Not set (follows domain default - may include RC4)
        4    = RC4 only (WILL BREAK on 2025 DC)
        24   = AES128 + AES256 (ideal)
        28   = RC4 + AES128 + AES256 (works but RC4 may be selected by KDC)
        31   = All types including DES (legacy)
    #>
    param([string]$DomainDN, [string]$KerberosScope = 'DiscoveredOnly')

    $results = @{
        RC4Only       = [System.Collections.Generic.List[PSObject]]::new()
        RC4WithAES    = [System.Collections.Generic.List[PSObject]]::new()
        NotSet        = [System.Collections.Generic.List[PSObject]]::new()
        AESOnly       = [System.Collections.Generic.List[PSObject]]::new()
        DESPresent    = [System.Collections.Generic.List[PSObject]]::new()
        TrustRC4Only  = [System.Collections.Generic.List[PSObject]]::new()
    }

    Write-Host "  Kerberos Scope: $KerberosScope" -ForegroundColor White

    # --- Computer Accounts ---
    Write-Host "  Scanning computer accounts..." -NoNewline

    if ($KerberosScope -eq 'DiscoveredOnly') {
        # Only scan computers found in Phase 1 inventory
        $computers = @()
        foreach ($key in $script:serverInventory.Keys) {
            $srvName = $script:serverInventory[$key].Name
            $found = Search-AD -SearchBase $DomainDN `
                -LdapFilter "(&(objectClass=computer)(cn=$srvName))" `
                -Properties @('name','msDS-SupportedEncryptionTypes','operatingSystem','servicePrincipalName')
            if ($found) { $computers += $found }
        }
    } elseif ($KerberosScope -eq 'AllServers') {
        # All server OS computer accounts
        $computers = Search-AD -SearchBase $DomainDN `
            -LdapFilter '(&(objectClass=computer)(operatingSystem=*Server*))' `
            -Properties @('name','msDS-SupportedEncryptionTypes','operatingSystem','servicePrincipalName')
    } else {
        # Full: all computer accounts
        $computers = Search-AD -SearchBase $DomainDN `
            -LdapFilter '(&(objectClass=computer)(objectCategory=computer))' `
            -Properties @('name','msDS-SupportedEncryptionTypes','operatingSystem','servicePrincipalName')
    }

    $compCount = 0
    foreach ($comp in $computers) {
        $encType = $comp.'msDS-SupportedEncryptionTypes'
        $entry = [PSCustomObject]@{
            Name = $comp.Name
            Type = 'Computer'
            EncryptionValue = $encType
            EncryptionLabel = Get-EncTypeLabel $encType
            OS = $comp.operatingSystem
            ADAttribute = 'msDS-SupportedEncryptionTypes'
            FixCmd = "Set-ADComputer '$($comp.Name)' -KerberosEncryptionType AES128,AES256"
        }
        Categorize-EncType -Entry $entry -Value $encType -Results $results
        $compCount++
    }
    Write-Host " $compCount" -ForegroundColor Green

    # --- Service Accounts (user accounts with SPNs) ---
    if ($KerberosScope -eq 'Full') {
        Write-Host "  Scanning service accounts..." -NoNewline
        $svcAccounts = Search-AD -SearchBase $DomainDN `
            -LdapFilter '(&(objectClass=user)(servicePrincipalName=*))' `
            -Properties @('name','msDS-SupportedEncryptionTypes','servicePrincipalName')

        $svcCount = 0
        foreach ($svc in $svcAccounts) {
            $encType = $svc.'msDS-SupportedEncryptionTypes'
            $entry = [PSCustomObject]@{
                Name = $svc.Name
                Type = 'ServiceAccount'
                EncryptionValue = $encType
                EncryptionLabel = Get-EncTypeLabel $encType
                OS = 'N/A'
                ADAttribute = 'msDS-SupportedEncryptionTypes'
                FixCmd = "Set-ADUser '$($svc.Name)' -KerberosEncryptionType AES128,AES256"
            }
            Categorize-EncType -Entry $entry -Value $encType -Results $results
            $svcCount++
        }
        Write-Host " $svcCount" -ForegroundColor Green
    } else {
        Write-Host "  Service accounts.......skipped (use -KerberosScope Full)" -ForegroundColor DarkGray
    }

    # --- gMSAs (always scan, small number) ---
    Write-Host "  Scanning gMSAs............." -NoNewline
    $gmsas = Search-AD -SearchBase $DomainDN `
        -LdapFilter '(objectClass=msDS-GroupManagedServiceAccount)' `
        -Properties @('name','msDS-SupportedEncryptionTypes')

    $gmsaCount = 0
    foreach ($g in $gmsas) {
        $encType = $g.'msDS-SupportedEncryptionTypes'
        $entry = [PSCustomObject]@{
            Name = $g.Name
            Type = 'gMSA'
            EncryptionValue = $encType
            EncryptionLabel = Get-EncTypeLabel $encType
            OS = 'N/A'
            ADAttribute = 'msDS-SupportedEncryptionTypes'
            FixCmd = "Set-ADServiceAccount -Identity '$($g.Name)' -KerberosEncryptionType AES128,AES256"
        }
        Categorize-EncType -Entry $entry -Value $encType -Results $results
        $gmsaCount++
    }
    Write-Host " $gmsaCount" -ForegroundColor Green

    # --- Trust Objects ---
    Write-Host "  Scanning trust objects......" -NoNewline
    $trusts = Search-AD -SearchBase "CN=System,$DomainDN" `
        -LdapFilter '(objectClass=trustedDomain)' `
        -Properties @('name','msDS-SupportedEncryptionTypes','trustDirection','trustType')

    $trustCount = 0
    foreach ($t in $trusts) {
        $encType = $t.'msDS-SupportedEncryptionTypes'
        $entry = [PSCustomObject]@{
            Name = $t.Name
            Type = 'Trust'
            EncryptionValue = $encType
            EncryptionLabel = Get-EncTypeLabel $encType
            OS = 'N/A'
            ADAttribute = 'msDS-SupportedEncryptionTypes'
            FixCmd = "ksetup /setenctypeattr $($t.Name) RC4-HMAC-MD5 AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96"
        }
        # Trusts default to RC4 only - this is the cross-domain killer
        if ($null -eq $encType -or $encType -eq 0 -or $encType -eq 4) {
            $results.TrustRC4Only.Add($entry)
        }
        Categorize-EncType -Entry $entry -Value $encType -Results $results
        $trustCount++
    }
    Write-Host " $trustCount" -ForegroundColor Green

    return $results
}

function Get-EncTypeLabel {
    param($Value)
    if ($null -eq $Value -or $Value -eq 0) { return 'NOT SET (domain default)' }
    $flags = @()
    if ($Value -band 0x1)  { $flags += 'DES_CBC_CRC' }
    if ($Value -band 0x2)  { $flags += 'DES_CBC_MD5' }
    if ($Value -band 0x4)  { $flags += 'RC4' }
    if ($Value -band 0x8)  { $flags += 'AES128' }
    if ($Value -band 0x10) { $flags += 'AES256' }
    return "$($flags -join '+') ($Value)"
}

function Categorize-EncType {
    param([PSObject]$Entry, $Value, [hashtable]$Results)
    if ($null -eq $Value -or $Value -eq 0) {
        $Results.NotSet.Add($Entry); return
    }
    $hasRC4  = [bool]($Value -band 0x4)
    $hasAES  = [bool](($Value -band 0x8) -or ($Value -band 0x10))
    $hasDES  = [bool](($Value -band 0x1) -or ($Value -band 0x2))

    if ($hasDES) { $Results.DESPresent.Add($Entry) }
    if ($hasRC4 -and -not $hasAES) { $Results.RC4Only.Add($Entry) }
    elseif ($hasRC4 -and $hasAES) { $Results.RC4WithAES.Add($Entry) }
    elseif (-not $hasRC4 -and $hasAES) { $Results.AESOnly.Add($Entry) }
}

#endregion

#region --- Remote Check Helpers ---

function Get-RemoteSmbConfig {
    param([string]$CN)
    try {
        Invoke-Command -ComputerName $CN -ScriptBlock {
            $s = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
            $c = Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
            @{ ServerRequire=$s.RequireSecuritySignature; ServerEnable=$s.EnableSecuritySignature
               ClientRequire=$c.RequireSecuritySignature; ClientEnable=$c.EnableSecuritySignature }
        } -EA Stop
    } catch {
        @{ ServerRequire='UNREACHABLE'; ServerEnable='UNREACHABLE'; ClientRequire='UNREACHABLE'; ClientEnable='UNREACHABLE' }
    }
}

function Get-RemoteRegValue {
    param([string]$CN, [string]$Path, [string]$Name)
    try {
        $r = Invoke-Command -ComputerName $CN -ScriptBlock {
            param($p,$n); try { (Get-ItemProperty -Path $p -Name $n -EA Stop).$n } catch { $null }
        } -ArgumentList $Path, $Name -EA Stop
        if ($null -eq $r) { return 'NOT SET' }; return $r
    } catch { return 'UNREACHABLE' }
}

function Get-RemoteKerbPolicy {
    <# Gets the Kerberos allowed encryption types from remote registry/policy #>
    param([string]$CN)
    try {
        $r = Invoke-Command -ComputerName $CN -ScriptBlock {
            # Check GPO-applied value first
            $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
                -Name 'SupportedEncryptionTypes' -EA SilentlyContinue
            if ($pol) { return @{ Value=$pol.SupportedEncryptionTypes; Source='GPO' } }
            # Check local Kerberos parameters
            $local = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
                -Name 'SupportedEncryptionTypes' -EA SilentlyContinue
            if ($local) { return @{ Value=$local.SupportedEncryptionTypes; Source='Registry' } }
            return @{ Value=$null; Source='NOT SET (OS default)' }
        } -EA Stop
        return $r
    } catch { return @{ Value='UNREACHABLE'; Source='UNREACHABLE' } }
}

function Get-RemoteOSBuild {
    param([string]$CN)
    try { Invoke-Command -ComputerName $CN -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).BuildNumber } -EA Stop }
    catch { 'UNREACHABLE' }
}

function Write-ColorStatus {
    param([string]$Label, [string]$Value, [string]$Status)
    $c = switch ($Status) { 'OK'{'Green'} 'WARNING'{'Yellow'} 'CRITICAL'{'Red'} 'UNREACHABLE'{'DarkGray'} default{'White'} }
    Write-Host "  $Label : " -NoNewline; Write-Host "$Value [$Status]" -ForegroundColor $c
}

function Write-RoleTag {
    param([string[]]$Roles)
    $c = @{ DC='Red'; Exchange='Magenta'; ExchangeDAG='Magenta'; FileCluster='Blue'; ClusterVNO='DarkBlue'; Witness='DarkYellow'
            CA='DarkCyan'; DFS='Blue'; Cluster='DarkYellow'; HyperV='Cyan'; Member='White' }
    Write-Host "  Roles: " -NoNewline
    for ($i=0; $i -lt $Roles.Count; $i++) {
        $rc = if ($c.ContainsKey($Roles[$i])) { $c[$Roles[$i]] } else { 'White' }
        Write-Host "[$($Roles[$i])]" -ForegroundColor $rc -NoNewline
        if ($i -lt $Roles.Count-1) { Write-Host " " -NoNewline }
    }
    Write-Host ""
}

function Get-RoleRisk {
    param([string[]]$Roles, [hashtable]$Smb, $LdapInt, $KerbPolicy, [bool]$Is2025)
    $risks = [System.Collections.Generic.List[string]]::new()
    $smbEnforced = $Smb.ServerRequire -eq $true

    # Kerberos encryption risk
    $kerbRC4Blocked = $false
    if ($KerbPolicy -and $KerbPolicy.Value -and $KerbPolicy.Value -ne 'UNREACHABLE') {
        $kv = [int]$KerbPolicy.Value
        $hasRC4 = [bool]($kv -band 0x4)
        $hasAES = [bool](($kv -band 0x8) -or ($kv -band 0x10))
        if ($hasAES -and -not $hasRC4) { $kerbRC4Blocked = $true }
    }
    # 2025 DCs block RC4 TGTs by default even without explicit policy
    if ($Is2025 -and 'DC' -in $Roles) { $kerbRC4Blocked = $true }

    foreach ($r in $Roles) {
        if ($smbEnforced) {
            switch ($r) {
                'DC'          { $risks.Add('CRITICAL - DC: SMB Signing -> SYSVOL/NETLOGON -> GPO -> Kerberos -> domain-wide auth') }
                'Exchange'    { $risks.Add('CRITICAL - Exchange: SMB Signing -> backend connectivity') }
                'ExchangeDAG' { $risks.Add('CRITICAL - DAG: SMB Signing -> log shipping -> DB replication -> mail flow dead') }
                'FileCluster' { $risks.Add('CRITICAL - File Cluster: SMB Signing -> shares dead') }
                'ClusterVNO'  { $risks.Add('WARNING - Cluster VNO: Virtual name, check physical cluster member nodes instead') }
                'Witness'     { $risks.Add('CRITICAL - Witness: SMB Signing -> quorum lost -> cluster offline') }
                'CA'          { $risks.Add('HIGH - CA: SMB Signing -> CRL/CDP -> cert validation broken') }
                'DFS'         { $risks.Add('HIGH - DFS: SMB Signing -> replication fails') }
                'Cluster'     { $risks.Add('HIGH - Cluster: SMB Signing -> inter-node fails') }
                'HyperV'      { $risks.Add('MEDIUM - Hyper-V: SMB Signing -> live migration may fail') }
            }
        }
        if ($kerbRC4Blocked -and $r -eq 'DC') {
            $risks.Add('HIGH - DC: RC4 TGTs blocked -> accounts with RC4-only or RC4+AES may fail auth (KDC selects RC4, client rejects)')
        }
        if ($LdapInt -eq 2 -and $r -eq 'DC') {
            $risks.Add('WARNING - DC: LDAP Signing required -> legacy unsigned binds fail')
        }
    }

    if ($risks.Count -eq 0) { return 'LOW' }
    foreach ($sev in @('CRITICAL','HIGH','MEDIUM','WARNING')) {
        $matched = $risks | Where-Object { $_ -match "^$sev" }
        if ($matched) { return ($matched -join '; ') }
    }
    return 'LOW'
}

#endregion
#endregion

#region ============ MODUS: READINESS ============
function Invoke-ModeReadiness {
    # Original lief OHNE StrictMode (implizite .Count-Emulation auf Skalaren/$null).
    # Modus-Scope: neutralisiert das globale v2 fuer diesen Modus + gerufene Helfer.
    Set-StrictMode -Off
    #region --- Main Execution ---

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  Windows Server 2025 Security Audit v4.1" -ForegroundColor Cyan
    Write-Host "  The Full Picture: SMB + LDAP + Kerberos RC4/AES + NTLM" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""

    $domainDN = Get-DomainDN
    $configDN = Get-ConfigDN -DomainDN $domainDN
    $services = "CN=Services,$configDN"
    Write-Host "  Domain   : $domainDN" -ForegroundColor White
    Write-Host "  Config   : $configDN" -ForegroundColor White
    Write-Host "  Services : $services" -ForegroundColor White
    Write-Host ""

    # === PHASE 1 ===
    Write-Host "=== PHASE 1: AD ROLE DISCOVERY ===" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Domain Controllers......." -NoNewline
    $n = Find-DomainControllers -DomainDN $domainDN -ConfigDN $configDN; Write-Host " $n" -ForegroundColor Green

    Write-Host "  Exchange Servers........." -NoNewline
    $n = Find-ExchangeServers -DomainDN $domainDN -ConfigDN $configDN; Write-Host " $n" -ForegroundColor Green

    Write-Host "  Certificate Authorities.." -NoNewline
    $n = Find-CertificateAuthorities -DomainDN $domainDN -ConfigDN $configDN; Write-Host " $n" -ForegroundColor Green

    Write-Host "  Cluster Nodes............" -NoNewline
    $n = Find-ClusterNodes -DomainDN $domainDN; Write-Host " $n" -ForegroundColor Green

    Write-Host "  DFS Servers.............." -NoNewline
    $n = Find-DFSServers -DomainDN $domainDN; Write-Host " $n" -ForegroundColor Green

    Write-Host "  Hyper-V Hosts............" -NoNewline
    $n = Find-HyperVServers -DomainDN $domainDN; Write-Host " $n" -ForegroundColor Green

    if ($Scope -eq 'AllServers') {
        Write-Host "  All domain servers (OS).." -NoNewline
        $allSrv = Find-AllDomainServers -DomainDN $domainDN
        Write-Host " $($allSrv.Total) (davon neu: $($allSrv.Added))" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "  Unique servers: $($script:serverInventory.Count)" -ForegroundColor Cyan
    Write-Host ""

    foreach ($key in ($script:serverInventory.Keys | Sort-Object)) {
        $srv = $script:serverInventory[$key]
        Write-Host "  $($srv.Name.PadRight(25))" -NoNewline
        Write-RoleTag -Roles $srv.Roles.ToArray()
    }
    Write-Host ""

    # === PHASE 1.5 ===
    Write-Host "=== PHASE 1.5: KERBEROS ENCRYPTION AUDIT (AD-only) ===" -ForegroundColor Yellow
    Write-Host ""

    $kerbAudit = Get-KerberosEncryptionAudit -DomainDN $domainDN -KerberosScope $KerberosScope
    Write-Host ""

    # RC4-only accounts (WILL BREAK on 2025 DC)
    if ($kerbAudit.RC4Only.Count -gt 0) {
        Write-Host "  !!! RC4-ONLY ACCOUNTS - WILL BREAK ON SERVER 2025 DC !!!" -ForegroundColor Red
        Write-Host "  These accounts cannot get Kerberos TGTs from a 2025 DC:" -ForegroundColor Red
        Write-Host ""
        foreach ($a in $kerbAudit.RC4Only | Select-Object -First 20) {
            Write-Host "    $($a.Type.PadRight(15)) $($a.Name.PadRight(25)) $($a.EncryptionLabel)" -ForegroundColor Red
        }
        if ($kerbAudit.RC4Only.Count -gt 20) {
            Write-Host "    ... and $($kerbAudit.RC4Only.Count - 20) more" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  FIX: Reset password (generates AES keys) or set:" -ForegroundColor Yellow
        Write-Host '  Set-ADUser/Set-ADComputer -KerberosEncryptionType AES128,AES256' -ForegroundColor Yellow
        Write-Host '  Set-ADServiceAccount -Identity <gMSA> -KerberosEncryptionType AES128,AES256' -ForegroundColor Yellow
        Write-Host ""
    }

    # RC4+AES accounts (risky: KDC may choose RC4, 2025 client rejects)
    if ($kerbAudit.RC4WithAES.Count -gt 0) {
        Write-Host "  --- RC4+AES ACCOUNTS - POTENTIAL MISMATCH RISK ---" -ForegroundColor Yellow
        Write-Host "  KDC may select RC4; if client is AES-only (2025 default), auth fails." -ForegroundColor Yellow
        Write-Host "  Count: $($kerbAudit.RC4WithAES.Count)" -ForegroundColor Yellow
        Write-Host "  AD-Attribut: msDS-SupportedEncryptionTypes (Wert 28 -> Ziel: 24)" -ForegroundColor DarkGray
        $gmsaRisk = $kerbAudit.RC4WithAES | Where-Object { $_.Type -eq 'gMSA' }
        if ($gmsaRisk.Count -gt 0) {
            Write-Host "  gMSAs at risk (value 28 -> should be 24):" -ForegroundColor Yellow
            foreach ($g in $gmsaRisk) {
                Write-Host "    $($g.Name.PadRight(25)) $($g.EncryptionLabel)" -ForegroundColor Yellow
            }
        }
        Write-Host ""
    }

    # Trust objects with RC4 only
    if ($kerbAudit.TrustRC4Only.Count -gt 0) {
        Write-Host "  !!! TRUST OBJECTS WITH RC4-ONLY - CROSS-DOMAIN AUTH WILL FAIL !!!" -ForegroundColor Red
        Write-Host "  Trusts default to RC4. Add AES with: ksetup /setenctypeattr" -ForegroundColor Red
        Write-Host "  AD-Attribut: msDS-SupportedEncryptionTypes auf Trust-Objekt in CN=System" -ForegroundColor DarkGray
        foreach ($t in $kerbAudit.TrustRC4Only) {
            Write-Host "    Trust: $($t.Name)  Enc: $($t.EncryptionLabel)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  FIX: On DC in trusted domain run:" -ForegroundColor Yellow
        Write-Host '  ksetup /setenctypeattr <trustingdomain.fqdn> RC4-HMAC-MD5 AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96' -ForegroundColor Yellow
        Write-Host ""
    }

    # NOT SET accounts
    if ($kerbAudit.NotSet.Count -gt 0) {
        Write-Host "  --- ACCOUNTS WITH NO EXPLICIT ENCRYPTION TYPE ---" -ForegroundColor DarkGray
        Write-Host "  Count: $($kerbAudit.NotSet.Count) (follow domain default - check DefaultDomainSupportedEncTypes)" -ForegroundColor DarkGray
        Write-Host "  AD-Attribut: msDS-SupportedEncryptionTypes = NULL/0 -> Ziel: explizit auf 24 setzen" -ForegroundColor DarkGray
        Write-Host "  Mid-2026 Microsoft will change assumed defaults to AES-only." -ForegroundColor DarkGray
        Write-Host ""
    }

    # DES accounts
    if ($kerbAudit.DESPresent.Count -gt 0) {
        Write-Host "  !!! DES ENCRYPTION STILL PRESENT !!!" -ForegroundColor Red
        Write-Host "  Count: $($kerbAudit.DESPresent.Count) - DES has been broken for decades." -ForegroundColor Red
        Write-Host "  AD-Attribut: msDS-SupportedEncryptionTypes (Wert 31 -> Ziel: 24)" -ForegroundColor DarkGray
        foreach ($d in $kerbAudit.DESPresent | Select-Object -First 10) {
            Write-Host "    $($d.Type.PadRight(15)) $($d.Name.PadRight(25)) $($d.EncryptionLabel)" -ForegroundColor Red
        }
        Write-Host ""
    }

    # Summary
    Write-Host "  KERBEROS ENCRYPTION SUMMARY:" -ForegroundColor Cyan
    Write-Host "  AES-only (safe)      : $($kerbAudit.AESOnly.Count)" -ForegroundColor Green
    Write-Host "  RC4+AES (risky)      : $($kerbAudit.RC4WithAES.Count)" -ForegroundColor Yellow
    Write-Host "  RC4-only (WILL BREAK): $($kerbAudit.RC4Only.Count)" -ForegroundColor $(if ($kerbAudit.RC4Only.Count -gt 0) {'Red'} else {'Green'})
    Write-Host "  NOT SET (domain def) : $($kerbAudit.NotSet.Count)" -ForegroundColor DarkGray
    Write-Host "  DES present (legacy) : $($kerbAudit.DESPresent.Count)" -ForegroundColor $(if ($kerbAudit.DESPresent.Count -gt 0) {'Red'} else {'Green'})
    Write-Host "  Trust RC4-only       : $($kerbAudit.TrustRC4Only.Count)" -ForegroundColor $(if ($kerbAudit.TrustRC4Only.Count -gt 0) {'Red'} else {'Green'})
    Write-Host ""

    if ($SkipRemoteCheck) {
        Write-Host "  -SkipRemoteCheck: Phase 2 skipped." -ForegroundColor Yellow
        if ($ExportCsv) {
            $disc = foreach ($key in $script:serverInventory.Keys) {
                $s = $script:serverInventory[$key]
                [PSCustomObject]@{ ComputerName=$s.Name; HostName=$s.HostName; Roles=($s.Roles -join ', '); OS=$s.OS }
            }
            $disc | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
            Write-Host "  Exported: $ExportCsv" -ForegroundColor Green

            # Also export Kerberos findings
            $kerbCsvPath = $ExportCsv -replace '\.csv$', '_KerberosAudit.csv'
            $kerbExport = @()
            foreach ($cat in @('RC4Only','RC4WithAES','AESOnly','NotSet','DESPresent','TrustRC4Only')) {
                foreach ($item in $kerbAudit[$cat]) {
                    $kerbExport += $item | Select-Object *, @{N='Category';E={$cat}}
                }
            }
            $kerbExport | Export-Csv -Path $kerbCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "  Kerberos audit: $kerbCsvPath" -ForegroundColor Green
        }
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "  Run without -SkipRemoteCheck for remote settings check." -ForegroundColor Cyan
        Write-Host "=================================================================" -ForegroundColor Cyan
        return
    }

    # === PHASE 2 ===
    Write-Host "=== PHASE 2: REMOTE SETTINGS CHECK ===" -ForegroundColor Yellow
    Write-Host ""

    $toCheck = switch ($Scope) {
        'DomainControllers' { $script:serverInventory.GetEnumerator() | Where-Object { 'DC' -in $_.Value.Roles } }
        'MemberServers'     { $script:serverInventory.GetEnumerator() | Where-Object { 'DC' -notin $_.Value.Roles } }
        'All'               { $script:serverInventory.GetEnumerator() }
        'AllServers'        { $script:serverInventory.GetEnumerator() }
    }

    $results = @()
    $roleImpacts = @{
        DC='SYSVOL/NETLOGON -> GPO -> Kerberos -> domain-wide auth'
        ExchangeDAG='DAG log shipping -> DB replication -> mailbox failover -> mail flow'
        Exchange='Backend content conversion, Outlook/OWA'
        FileCluster='Clustered shares dead for non-signing clients'
        ClusterVNO='Virtual cluster name — check physical member nodes for actual risk'
        Witness='Quorum witness share -> cluster loses vote -> offline'
        CA='CRL/CDP -> cert validation -> LDAPS/HTTPS/802.1x/enrollment'
        DFS='DFS namespace/replication between nodes'
        Cluster='Inter-node communication (physical member)'
        HyperV='Live migration, shared storage'
        Server='Member server ohne erkannte Rolle — Signing-Enforcement betrifft dessen Clients'
    }

    foreach ($entry in $toCheck) {
        $srv = $entry.Value; $name = $srv.HostName; $dn = $srv.Name; $roles = $srv.Roles.ToArray()

        Write-Host "--- ${dn} ---" -ForegroundColor White
        Write-RoleTag -Roles $roles

        if (-not (Test-Connection -ComputerName $name -Count 1 -Quiet -EA SilentlyContinue)) {
            Write-Host "  OFFLINE" -ForegroundColor DarkGray; Write-Host ""
            $results += [PSCustomObject]@{ ComputerName=$dn; Roles=($roles -join ', '); OSBuild='UNREACHABLE'
                IsServer2025='?'; SMB_Server_Require='UNREACHABLE'; SMB_Client_Require='UNREACHABLE'
                LDAP_ServerIntegrity='N/A'; LDAP_ChannelBinding='N/A'; NTLM_Restrict='N/A'
                Kerb_EncTypes='N/A'; Kerb_Source='N/A'; RiskLevel='UNREACHABLE' }
            continue
        }

        $build = Get-RemoteOSBuild -ComputerName $name
        $is2025 = $false
        if ($build -ne 'UNREACHABLE') {
            try { $is2025 = ([int]$build) -ge 26100 } catch { $is2025 = $false }
        }
        $buildLabel = if ($build -eq 'UNREACHABLE') { 'UNREACHABLE' } elseif ($is2025) { "$build [2025]" } else { "$build" }
        Write-Host "  Build: $buildLabel" -ForegroundColor $(if ($build -eq 'UNREACHABLE') { 'DarkGray' } elseif ($is2025) { 'Yellow' } else { 'White' })

        # SMB
        $smb = Get-RemoteSmbConfig -CN $name
        $critRoles = @('DC','Exchange','ExchangeDAG','FileCluster','Witness','Cluster')
        $smbSev = if ($smb.ServerRequire -eq $true) {
            if ($roles | Where-Object { $_ -in $critRoles }) { 'CRITICAL' } else { 'WARNING' }
        } elseif ($smb.ServerRequire -eq 'UNREACHABLE') { 'UNREACHABLE' } else { 'OK' }
        Write-ColorStatus "SMB Server Require" "$($smb.ServerRequire)" $smbSev
        if ($smb.ServerRequire -ne 'UNREACHABLE') { Write-Host "    -> Get-SmbServerConfiguration | GPO: 'Microsoft network server: Digitally sign communications (always)'" -ForegroundColor DarkGray }

        $cliSev = if ($smb.ClientRequire -eq $true) { 'WARNING' } elseif ($smb.ClientRequire -eq 'UNREACHABLE') { 'UNREACHABLE' } else { 'OK' }
        Write-ColorStatus "SMB Client Require" "$($smb.ClientRequire)" $cliSev
        if ($smb.ClientRequire -ne 'UNREACHABLE') { Write-Host "    -> Get-SmbClientConfiguration | GPO: 'Microsoft network client: Digitally sign communications (always)'" -ForegroundColor DarkGray }

        # Kerberos Encryption Policy
        $kerbPol = Get-RemoteKerbPolicy -CN $name
        $kerbLabel = if ($kerbPol.Value -eq 'UNREACHABLE') { 'UNREACHABLE' }
            elseif ($null -eq $kerbPol.Value) { "NOT SET ($($kerbPol.Source))" }
            else { "$(Get-EncTypeLabel $kerbPol.Value) via $($kerbPol.Source)" }

        $kerbSev = 'OK'
        if ($kerbPol.Value -ne 'UNREACHABLE' -and $null -ne $kerbPol.Value) {
            $kv = [int]$kerbPol.Value
            $kHasRC4 = [bool]($kv -band 0x4)
            $kHasAES = [bool](($kv -band 0x8) -or ($kv -band 0x10))
            if (-not $kHasAES) { $kerbSev = 'CRITICAL' }
            elseif ($kHasAES -and -not $kHasRC4 -and $is2025) { $kerbSev = 'OK' }
            elseif ($kHasAES -and -not $kHasRC4 -and -not $is2025) { $kerbSev = 'WARNING' }
        }
        if ($is2025 -and 'DC' -in $roles) {
            Write-ColorStatus "Kerberos Enc Policy" $kerbLabel $kerbSev
            Write-Host "    -> GPO: 'Network security: Configure encryption types allowed for Kerberos'" -ForegroundColor DarkGray
            Write-ColorStatus "RC4 TGT Issuance" "BLOCKED (2025 DC default)" "WARNING"
        } else {
            Write-ColorStatus "Kerberos Enc Policy" $kerbLabel $kerbSev
            if ($kerbPol.Value -ne 'UNREACHABLE') { Write-Host "    -> GPO: 'Network security: Configure encryption types allowed for Kerberos' | Reg: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes" -ForegroundColor DarkGray }
        }

        # LDAP / NTLM (DCs only)
        $ldapInt = 'N/A'; $ldapCB = 'N/A'; $ntlm = 'N/A'
        if ('DC' -in $roles) {
            $ldapInt = Get-RemoteRegValue $name 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
            $liLabel = switch ($ldapInt) { 0{'None'}; 1{'If supported'}; 2{'Always'}; 'NOT SET'{'NOT SET (OS default)'}; default{$ldapInt} }
            $liSev = if ($ldapInt -eq 2) { 'WARNING' } elseif ($ldapInt -eq 'UNREACHABLE') { 'UNREACHABLE' } else { 'OK' }
            Write-ColorStatus "LDAP Signing" $liLabel $liSev
            if ($ldapInt -ne 'UNREACHABLE') { Write-Host "    -> Reg: HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity (0=None,1=Prefer,2=Always)" -ForegroundColor DarkGray }

            $ldapCB = Get-RemoteRegValue $name 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
            $cbLabel = switch ($ldapCB) { 0{'Never'}; 1{'When supported'}; 2{'Always'}; 'NOT SET'{'NOT SET'}; default{$ldapCB} }
            $cbSev = if ($ldapCB -eq 2) { 'WARNING' } elseif ($ldapCB -eq 'UNREACHABLE') { 'UNREACHABLE' } else { 'OK' }
            Write-ColorStatus "LDAP Channel Binding" $cbLabel $cbSev
            if ($ldapCB -ne 'UNREACHABLE') { Write-Host "    -> Reg: HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding" -ForegroundColor DarkGray }

            $ntlm = Get-RemoteRegValue $name 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RestrictNTLMInDomain'
            $ntLabel = switch ($ntlm) { 0{'Disabled'}; 1{'Deny acct->srv'}; 2{'Deny acct'}; 3{'Deny srv'}; 5{'Deny all->all'}; 7{'Deny all'}; 'NOT SET'{'NOT SET'}; default{$ntlm} }
            $ntSev = if ($ntlm -ge 3 -and $ntlm -ne 'NOT SET') { 'WARNING' } elseif ($ntlm -eq 'UNREACHABLE') { 'UNREACHABLE' } else { 'OK' }
            Write-ColorStatus "NTLM Restriction" $ntLabel $ntSev
            if ($ntlm -ne 'UNREACHABLE') { Write-Host "    -> Reg: HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain" -ForegroundColor DarkGray }
        }

        # Risk
        $risk = Get-RoleRisk -Roles $roles -Smb $smb -LdapInt $ldapInt -KerbPolicy $kerbPol -Is2025 $is2025
        $rc = if ($risk -match 'CRITICAL') {'Red'} elseif ($risk -match 'HIGH') {'Red'} elseif ($risk -match 'MEDIUM|WARNING') {'Yellow'} else {'Green'}
        foreach ($line in ($risk -split '; ')) { Write-Host "  RISK: " -NoNewline; Write-Host $line -ForegroundColor $rc }
        Write-Host ""

        $results += [PSCustomObject]@{
            ComputerName=$dn; Roles=($roles -join ', '); OSBuild=$build; IsServer2025=$is2025
            SMB_Server_Require="$($smb.ServerRequire)"; SMB_Client_Require="$($smb.ClientRequire)"
            SMB_Server_GPO='Microsoft network server: Digitally sign communications (always)'
            SMB_Server_Cmdlet='Get-SmbServerConfiguration | Select RequireSecuritySignature'
            SMB_Client_GPO='Microsoft network client: Digitally sign communications (always)'
            SMB_Client_Cmdlet='Get-SmbClientConfiguration | Select RequireSecuritySignature'
            Kerb_EncTypes=$kerbLabel; Kerb_Source=$kerbPol.Source
            Kerb_GPO='Network security: Configure encryption types allowed for Kerberos'
            Kerb_RegKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes'
            LDAP_ServerIntegrity="$ldapInt"; LDAP_ChannelBinding="$ldapCB"; NTLM_Restrict="$ntlm"
            LDAP_RegKey='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
            LDAP_CB_RegKey='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
            NTLM_RegKey='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RestrictNTLMInDomain'
            RiskLevel=$risk
        }
    }

    #endregion

    #region --- Summary & Auto-Report ---

    # Ensure output directory
    $reportDir = $ReportPath
    if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'

    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""

    $reachable = $results | Where-Object { $_.RiskLevel -ne 'UNREACHABLE' }
    $crit = ($results | Where-Object { $_.RiskLevel -match 'CRITICAL' }).Count
    $high = ($results | Where-Object { $_.RiskLevel -match 'HIGH' -and $_.RiskLevel -notmatch 'CRITICAL' }).Count
    $med  = ($results | Where-Object { $_.RiskLevel -match 'MEDIUM' }).Count
    $low  = ($results | Where-Object { $_.RiskLevel -eq 'LOW' }).Count
    $off  = ($results | Where-Object { $_.RiskLevel -eq 'UNREACHABLE' }).Count
    $s25  = ($results | Where-Object { $_.IsServer2025 -eq $true }).Count

    Write-Host "  Checked    : $($results.Count)   (Server 2025: ${s25})" -ForegroundColor White
    Write-Host "  CRITICAL   : $crit" -ForegroundColor $(if ($crit -gt 0) {'Red'} else {'Green'})
    Write-Host "  HIGH       : $high" -ForegroundColor $(if ($high -gt 0) {'Red'} else {'Green'})
    Write-Host "  MEDIUM     : $med" -ForegroundColor $(if ($med -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  LOW        : $low" -ForegroundColor Green
    Write-Host "  OFFLINE    : $off" -ForegroundColor $(if ($off -gt 0) {'DarkGray'} else {'Green'})
    Write-Host ""

    # --- Majority Analysis ---
    Write-Host "=== MAJORITY ANALYSIS ===" -ForegroundColor Yellow
    Write-Host ""

    $smbServerOn  = ($reachable | Where-Object { $_.SMB_Server_Require -eq 'True' }).Count
    $smbServerOff = ($reachable | Where-Object { $_.SMB_Server_Require -eq 'False' }).Count
    $smbClientOn  = ($reachable | Where-Object { $_.SMB_Client_Require -eq 'True' }).Count
    $smbClientOff = ($reachable | Where-Object { $_.SMB_Client_Require -eq 'False' }).Count
    $smbTotal     = $smbServerOn + $smbServerOff

    $smbServerPct = if ($smbTotal -gt 0) { [math]::Round(($smbServerOn / $smbTotal) * 100, 1) } else { 0 }
    $smbClientPct = if ($smbTotal -gt 0) { [math]::Round(($smbClientOn / $smbTotal) * 100, 1) } else { 0 }

    Write-Host "  SMB Server Signing Required : ${smbServerOn}/${smbTotal} (${smbServerPct}%)" -ForegroundColor $(if ($smbServerPct -ge 80) {'Green'} elseif ($smbServerPct -ge 50) {'Yellow'} else {'Red'})
    Write-Host "  SMB Client Signing Required : ${smbClientOn}/${smbTotal} (${smbClientPct}%)" -ForegroundColor $(if ($smbClientPct -ge 80) {'Green'} elseif ($smbClientPct -ge 50) {'Yellow'} else {'Red'})

    $kerbSafe    = $kerbAudit.AESOnly.Count
    $kerbRisky   = $kerbAudit.RC4WithAES.Count
    $kerbBroken  = $kerbAudit.RC4Only.Count
    $kerbNotSet  = $kerbAudit.NotSet.Count
    $kerbDES     = $kerbAudit.DESPresent.Count
    $kerbTrust   = $kerbAudit.TrustRC4Only.Count
    $kerbTotal   = $kerbSafe + $kerbRisky + $kerbBroken + $kerbNotSet
    $kerbSafePct = if ($kerbTotal -gt 0) { [math]::Round(($kerbSafe / $kerbTotal) * 100, 1) } else { 0 }

    Write-Host "  Kerberos AES-only (safe)    : ${kerbSafe}/${kerbTotal} (${kerbSafePct}%)" -ForegroundColor $(if ($kerbSafePct -ge 80) {'Green'} elseif ($kerbSafePct -ge 50) {'Yellow'} else {'Red'})
    Write-Host "  Kerberos RC4+AES (risky)    : $kerbRisky" -ForegroundColor $(if ($kerbRisky -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  Kerberos RC4-only (broken)  : $kerbBroken" -ForegroundColor $(if ($kerbBroken -gt 0) {'Red'} else {'Green'})
    Write-Host "  Trusts without AES          : $kerbTrust" -ForegroundColor $(if ($kerbTrust -gt 0) {'Red'} else {'Green'})
    Write-Host "  DES still present           : $kerbDES" -ForegroundColor $(if ($kerbDES -gt 0) {'Red'} else {'Green'})
    Write-Host ""

    # --- Recommendations ---
    Write-Host "=== RECOMMENDATIONS ===" -ForegroundColor Yellow
    Write-Host ""

    $recommendations = [System.Collections.Generic.List[PSObject]]::new()

    if ($smbServerPct -ge 90) {
        $smbRec = "SMB Signing ON on ${smbServerPct}%. Majority enforces. Enable on remaining $smbServerOff servers. Do NOT disable."
        Write-Host "  [SMB] $smbRec" -ForegroundColor Green
        $recommendations.Add([PSCustomObject]@{ Area='SMB Signing'; Status='MAJORITY ON'; Recommendation=$smbRec; Priority='LOW' })
    } elseif ($smbServerPct -ge 50) {
        $smbRec = "SMB Signing MIXED: ${smbServerPct}% ON. MISMATCH ZONE. Either enable on all or disable on minority causing failures."
        Write-Host "  [SMB] $smbRec" -ForegroundColor Yellow
        $recommendations.Add([PSCustomObject]@{ Area='SMB Signing'; Status='MIXED - DANGER'; Recommendation=$smbRec; Priority='HIGH' })
    } elseif ($smbServerOn -gt 0) {
        $smbRec = "SMB Signing ON on only ${smbServerPct}%. These few REJECT connections from majority. Disable on minority (quick fix) or plan rollout."
        Write-Host "  [SMB] $smbRec" -ForegroundColor Red
        $recommendations.Add([PSCustomObject]@{ Area='SMB Signing'; Status='MINORITY ON - MISMATCH'; Recommendation=$smbRec; Priority='CRITICAL' })
    } else {
        $smbRec = "SMB Signing OFF everywhere. No mismatch. Plan rollout before introducing 2025 DCs."
        Write-Host "  [SMB] $smbRec" -ForegroundColor DarkGray
        $recommendations.Add([PSCustomObject]@{ Area='SMB Signing'; Status='ALL OFF'; Recommendation=$smbRec; Priority='MEDIUM' })
    }

    if ($kerbBroken -gt 0) {
        $kRec = "$kerbBroken RC4-ONLY accounts WILL BREAK on 2025 DCs. Reset passwords or set AES IMMEDIATELY."
        Write-Host "  [KERB] $kRec" -ForegroundColor Red
        $recommendations.Add([PSCustomObject]@{ Area='Kerberos RC4-Only'; Status='BROKEN'; Recommendation=$kRec; Priority='CRITICAL' })
    }
    if ($kerbRisky -gt 0) {
        $kRec = "$kerbRisky RC4+AES accounts. KDC may select RC4, 2025 client rejects. Migrate to AES-only in batches."
        Write-Host "  [KERB] $kRec" -ForegroundColor Yellow
        $recommendations.Add([PSCustomObject]@{ Area='Kerberos RC4+AES'; Status='RISKY'; Recommendation=$kRec; Priority='HIGH' })
    }
    if ($kerbTrust -gt 0) {
        $kRec = "$kerbTrust trusts without AES. Cross-domain auth fails on 2025 KDC. Run ksetup /setenctypeattr."
        Write-Host "  [TRUST] $kRec" -ForegroundColor Red
        $recommendations.Add([PSCustomObject]@{ Area='Trust Encryption'; Status='RC4-ONLY'; Recommendation=$kRec; Priority='CRITICAL' })
    }
    if ($kerbDES -gt 0) {
        $kRec = "$kerbDES accounts with DES (broken since 2005). Set msDS-SupportedEncryptionTypes to 24 or 28."
        Write-Host "  [DES] $kRec" -ForegroundColor Red
        $recommendations.Add([PSCustomObject]@{ Area='DES Encryption'; Status='LEGACY RISK'; Recommendation=$kRec; Priority='HIGH' })
    }

    $ldapAlways = ($reachable | Where-Object { $_.LDAP_ServerIntegrity -eq '2' }).Count
    if ($ldapAlways -gt 0) {
        $lRec = "$ldapAlways DC(s) enforce LDAP Signing. Check Event ID 2889 for unsigned bind attempts."
        Write-Host "  [LDAP] $lRec" -ForegroundColor Yellow
        $recommendations.Add([PSCustomObject]@{ Area='LDAP Signing'; Status='ENFORCED'; Recommendation=$lRec; Priority='MEDIUM' })
    }
    Write-Host ""

    # --- Generate Reports ---
    Write-Host "=== GENERATING REPORTS ===" -ForegroundColor Yellow
    Write-Host ""

    # 1. Main report (semicolon delimited)
    $mainReportPath = "${reportDir}\SMB_Kerberos_report_${ts}.csv"
    $results | Export-Csv -Path $mainReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "  Main report     : $mainReportPath" -ForegroundColor Green

    # 2. Kerberos audit detail
    $kerbReportPath = "${reportDir}\SMB_Kerberos_report_${ts}_KerberosAudit.csv"
    $kerbExport = @()
    foreach ($cat in @('RC4Only','RC4WithAES','AESOnly','NotSet','DESPresent','TrustRC4Only')) {
        foreach ($item in $kerbAudit[$cat]) {
            $kerbExport += $item | Select-Object *, @{N='Category';E={$cat}}
        }
    }
    if ($kerbExport.Count -gt 0) {
        $kerbExport | Export-Csv -Path $kerbReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Kerberos audit  : $kerbReportPath" -ForegroundColor Green
    }

    # 3. Recommendations
    $recReportPath = "${reportDir}\SMB_Kerberos_report_${ts}_recommendations.csv"
    $recommendations | Export-Csv -Path $recReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "  Recommendations : $recReportPath" -ForegroundColor Green

    # 4. URGENT FIX — actionable quick wins with exact commands
    $urgentFixPath = "${reportDir}\SMB_Kerberos_report_${ts}_urgent_fix.csv"
    $urgentFixes = [System.Collections.Generic.List[PSObject]]::new()

    # SMB mismatch fixes
    if ($smbServerPct -lt 90 -and $smbServerPct -gt 0) {
        if ($smbServerPct -ge 50) {
            $fixTargets = $reachable | Where-Object { $_.SMB_Server_Require -eq 'False' }
            foreach ($ft in $fixTargets) {
                $urgentFixes.Add([PSCustomObject]@{
                    ComputerName=$ft.ComputerName; Roles=$ft.Roles; Issue='SMB Signing OFF (majority ON)'
                    Fix='Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
                    GPO='Microsoft network server: Digitally sign communications (always) -> Enabled'
                    Priority='HIGH'; RiskIfIgnored='Accepts unsigned connections in signed network'
                })
            }
        } else {
            $fixTargets = $reachable | Where-Object { $_.SMB_Server_Require -eq 'True' }
            foreach ($ft in $fixTargets) {
                $urgentFixes.Add([PSCustomObject]@{
                    ComputerName=$ft.ComputerName; Roles=$ft.Roles; Issue='SMB Signing ON (majority OFF) -> REJECTS CONNECTIONS'
                    Fix='Set-SmbServerConfiguration -RequireSecuritySignature $false -Force'
                    GPO='Microsoft network server: Digitally sign communications (always) -> Disabled'
                    Priority='CRITICAL'; RiskIfIgnored='Rejects connections from majority of network'
                })
            }
        }
    }

    # RC4-only accounts
    foreach ($a in $kerbAudit.RC4Only) {
        $fixCmd = if ($a.Type -eq 'gMSA') { "Set-ADServiceAccount -Identity '$($a.Name)' -KerberosEncryptionType AES128,AES256" }
                  elseif ($a.Type -eq 'Computer') { "Set-ADComputer '$($a.Name)' -KerberosEncryptionType AES128,AES256" }
                  else { "Set-ADUser '$($a.Name)' -KerberosEncryptionType AES128,AES256  # or reset password" }
        $urgentFixes.Add([PSCustomObject]@{
            ComputerName=$a.Name; Roles=$a.Type; Issue="RC4-ONLY ($($a.EncryptionLabel)) -> BREAKS on 2025 DC"
            Fix=$fixCmd; GPO='N/A - per account'; Priority='CRITICAL'; RiskIfIgnored='Cannot authenticate on 2025 DC'
        })
    }

    # Trusts without AES
    foreach ($t in $kerbAudit.TrustRC4Only) {
        $urgentFixes.Add([PSCustomObject]@{
            ComputerName=$t.Name; Roles='Trust'; Issue="No AES ($($t.EncryptionLabel)) -> cross-domain auth fails"
            Fix="ksetup /setenctypeattr $($t.Name) RC4-HMAC-MD5 AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96"
            GPO='Or: Set-ADObject on trust, add AES to msDS-SupportedEncryptionTypes'
            Priority='CRITICAL'; RiskIfIgnored='All cross-domain auth fails on 2025 DCs'
        })
    }

    # DES accounts (DCs first)
    foreach ($d in ($kerbAudit.DESPresent | Sort-Object { if ($_.Name -match 'DC') { 0 } else { 1 } })) {
        $urgentFixes.Add([PSCustomObject]@{
            ComputerName=$d.Name; Roles=$d.Type; Issue="DES enabled ($($d.EncryptionLabel))"
            Fix="Set-ADComputer '$($d.Name)' -KerberosEncryptionType AES128,AES256"
            GPO='Kerberos encryption types -> uncheck DES'; Priority='HIGH'; RiskIfIgnored='DES broken, security + compat risk'
        })
    }

    # gMSAs with RC4+AES
    foreach ($g in ($kerbAudit.RC4WithAES | Where-Object { $_.Type -eq 'gMSA' })) {
        $urgentFixes.Add([PSCustomObject]@{
            ComputerName=$g.Name; Roles='gMSA'; Issue="RC4+AES (28) -> KDC may pick RC4, 2025 rejects"
            Fix="Set-ADServiceAccount -Identity '$($g.Name)' -KerberosEncryptionType AES128,AES256"
            GPO='N/A - per account'; Priority='HIGH'; RiskIfIgnored='gMSA may fail on 2025 hosts'
        })
    }

    if ($urgentFixes.Count -gt 0) {
        # Sort by priority: CRITICAL first, then HIGH
        $urgentFixes = $urgentFixes | Sort-Object { switch ($_.Priority) { 'CRITICAL'{0} 'HIGH'{1} 'MEDIUM'{2} default{3} } }
        $urgentFixes | Export-Csv -Path $urgentFixPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  URGENT FIXES    : $urgentFixPath ($($urgentFixes.Count) items)" -ForegroundColor Red
    } else {
        Write-Host "  Urgent fixes    : None needed!" -ForegroundColor Green
    }

    # Backwards compat
    if ($ExportCsv) {
        try { $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'; Write-Host "  Custom export   : $ExportCsv" -ForegroundColor Green }
        catch { Write-Host "  Export failed: $_" -ForegroundColor Red }
    }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  Vier Sicherheits-Defaults. Vor Server 2025 Installation pruefen." -ForegroundColor Cyan
    Write-Host "  Reports in      : $reportDir" -ForegroundColor White
    Write-Host "  Referenzen:" -ForegroundColor DarkGray
    Write-Host "  - SMB  : https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/" -ForegroundColor DarkGray
    Write-Host "  - RC4  : https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos" -ForegroundColor DarkGray
    Write-Host "  - 2025 : https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025" -ForegroundColor DarkGray
    Write-Host "  - Franky: https://www.frankysweb.de/en/windows-server-2025-domain-controller-inplace-upgrade/" -ForegroundColor DarkGray
    Write-Host "  - Born : https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/" -ForegroundColor DarkGray
    Write-Host "  - MS   : https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/" -ForegroundColor DarkGray
    Write-Host "  - SMB-DE: https://learn.microsoft.com/de-de/windows-server/storage/file-server/smb-security-hardening" -ForegroundColor DarkGray
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
#endregion

#region ============ MODUS: PROVE ============
function Invoke-ModeProve {
    # Original lief OHNE StrictMode — Modus-Scope wie bei Readiness.
    Set-StrictMode -Off
    # Kapselung: eigene Helfer (Get-EncLabel/Get-XmlField-Variante) bleiben lokal
    $ExportPath = $ReportPath
    if (-not (Test-Path $ExportPath)) { New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null }
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $msBack = $Hours * 3600 * 1000  # milliseconds for timediff

    # Encryption type lookup
    $script:encTypes = @{
        '0x1'='DES-CBC-CRC'; '0x3'='DES-CBC-MD5'; '0x11'='AES128'; '0x12'='AES256'
        '0x17'='RC4-HMAC'; '0x18'='RC4-HMAC-EXP'; '0xffffffff'='FAIL/NO-KEY'
    }

    function Get-EncLabel {
        param([string]$Value)
        $v = $Value.Trim().ToLower()
        if ($script:encTypes.ContainsKey($v)) { return $script:encTypes[$v] }
        # Try decimal
        $decMap = @{ '1'='DES-CBC-CRC'; '3'='DES-CBC-MD5'; '17'='AES128'; '18'='AES256'; '23'='RC4-HMAC'; '24'='RC4-HMAC-EXP' }
        if ($decMap.ContainsKey($v)) { return $decMap[$v] }
        return "Unknown ($Value)"
    }

    function Get-XmlField {
        param([xml]$EventXml, [string]$FieldName)
        $node = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
        if ($node) { return $node.'#text' }
        return $null
    }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  RC4 Kerberos Pruefung v3.0 (FilterXML)" -ForegroundColor Cyan
    Write-Host "  Zeitraum: letzte $Hours Stunden auf $(hostname)" -ForegroundColor Cyan
    Write-Host "  MaxEvents pro Pruefung: $MaxEvents" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""

    #region --- CountOnly Mode (wevtutil — fastest) ---

    if ($CountOnly) {
        Write-Host "=== SCHNELLMODUS (wevtutil) ===" -ForegroundColor Yellow
        Write-Host ""

        # RC4 TGTs
        Write-Host "  RC4 TGTs (4768, EncType=0x17)..." -NoNewline
        $rc4TgtCount = 0
        try {
            $out = wevtutil qe Security /q:"*[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) <= $msBack]]] and *[EventData[Data[@Name='TicketEncryptionType']='0x17']]" /c:$MaxEvents /f:text 2>&1
            $rc4TgtCount = ($out | Select-String 'Event\[' | Measure-Object).Count
            # Alternative count method
            if ($rc4TgtCount -eq 0) { $rc4TgtCount = ($out | Where-Object { $_ -match 'TicketEncryptionType' } | Measure-Object).Count }
        } catch { }
        Write-Host " $rc4TgtCount" -ForegroundColor $(if ($rc4TgtCount -gt 0) {'Red'} else {'Green'})

        # RC4 Service Tickets
        Write-Host "  RC4 Service Tickets (4769)....." -NoNewline
        $rc4SvcCount = 0
        try {
            $out = wevtutil qe Security /q:"*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= $msBack]]] and *[EventData[Data[@Name='TicketEncryptionType']='0x17']]" /c:$MaxEvents /f:text 2>&1
            $rc4SvcCount = ($out | Where-Object { $_ -match 'TicketEncryptionType' } | Measure-Object).Count
        } catch { }
        Write-Host " $rc4SvcCount" -ForegroundColor $(if ($rc4SvcCount -gt 0) {'Red'} else {'Green'})

        # Kerberos errors
        Write-Host "  Kerberos EncType errors (14)..." -NoNewline
        $errCount = 0
        try {
            $out = wevtutil qe System /q:"*[System[(EventID=14) and TimeCreated[timediff(@SystemTime) <= $msBack]]]" /c:$MaxEvents /f:text 2>&1
            $errCount = ($out | Where-Object { $_ -match 'Event\[|EventID' } | Measure-Object).Count
        } catch { }
        Write-Host " $errCount" -ForegroundColor $(if ($errCount -gt 0) {'Red'} else {'Green'})

        # SMB rejections
        Write-Host "  SMB Rejections (1005/1006)....." -NoNewline
        $smbCount = 0
        try {
            $out = wevtutil qe Microsoft-Windows-SMBServer/Operational /q:"*[System[(EventID=1005 or EventID=1006) and TimeCreated[timediff(@SystemTime) <= $msBack]]]" /c:$MaxEvents /f:text 2>&1
            $smbCount = ($out | Where-Object { $_ -match 'Event\[|EventID' } | Measure-Object).Count
        } catch { }
        Write-Host " $smbCount" -ForegroundColor $(if ($smbCount -gt 0) {'Red'} else {'Green'})

        # RC4 Renewals
        Write-Host "  RC4 Renewals (4770)..........." -NoNewline
        $renewCount = 0
        try {
            $out = wevtutil qe Security /q:"*[System[(EventID=4770) and TimeCreated[timediff(@SystemTime) <= $msBack]]] and *[EventData[Data[@Name='TicketEncryptionType']='0x17']]" /c:$MaxEvents /f:text 2>&1
            $renewCount = ($out | Where-Object { $_ -match 'TicketEncryptionType' } | Measure-Object).Count
        } catch { }
        Write-Host " $renewCount" -ForegroundColor $(if ($renewCount -gt 0) {'Red'} else {'Green'})

        # Pre-Auth Failed
        Write-Host "  Pre-Auth Fehler (4771)........" -NoNewline
        $preAuthCount = 0
        try {
            $out = wevtutil qe Security /q:"*[System[(EventID=4771) and TimeCreated[timediff(@SystemTime) <= $msBack]]]" /c:$MaxEvents /f:text 2>&1
            $preAuthCount = ($out | Where-Object { $_ -match 'Event\[|TargetUserName' } | Measure-Object).Count
        } catch { }
        Write-Host " $preAuthCount" -ForegroundColor $(if ($preAuthCount -gt 50) {'Red'} elseif ($preAuthCount -gt 0) {'Yellow'} else {'Green'})

        # Lockouts
        Write-Host "  Account Lockouts (4740)......." -NoNewline
        $lockCount = 0
        try {
            $out = wevtutil qe Security /q:"*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= $msBack]]]" /c:$MaxEvents /f:text 2>&1
            $lockCount = ($out | Where-Object { $_ -match 'Event\[|TargetUserName' } | Measure-Object).Count
        } catch { }
        Write-Host " $lockCount" -ForegroundColor $(if ($lockCount -gt 20) {'Red'} elseif ($lockCount -gt 0) {'Yellow'} else {'Green'})

        # Unsigned LDAP Binds
        Write-Host "  Unsigned LDAP Binds (2889)...." -NoNewline
        $ldapCount = 0
        try {
            $out = wevtutil qe "Directory Service" /q:"*[System[(EventID=2889) and TimeCreated[timediff(@SystemTime) <= $msBack]]]" /c:$MaxEvents /f:text 2>&1
            $ldapCount = ($out | Where-Object { $_ -match 'Event\[|EventID' } | Measure-Object).Count
        } catch { }
        Write-Host " $ldapCount" -ForegroundColor $(if ($ldapCount -gt 50) {'Red'} elseif ($ldapCount -gt 0) {'Yellow'} else {'Green'})

        Write-Host ""
        if ($rc4TgtCount -gt 0 -or $rc4SvcCount -gt 0) {
            Write-Host "  !!! RC4 WIRD AKTIV VERWENDET — BRICHT AUF 2025 DC !!!" -ForegroundColor Red
        } else {
            Write-Host "  Keine RC4-Nutzung erkannt. Kerberos-Auditing aktivieren falls noch nicht geschehen:" -ForegroundColor Green
            Write-Host '  auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable' -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Run without -CountOnly for detailed analysis with account names." -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    #endregion

    #region --- Check 1: RC4 TGTs (Event 4768 via FilterXML) ---

    # Boot-Fenster ermitteln (Rausch-Filter fuer Events die ein Reboot by design erzeugt)
    # Vorinitialisierung zwingend: die Boot-Listen werden in try-Bloecken gefuellt.
    # Greift ein catch (keine Events), waeren sie sonst undefiniert — und
    # @($undefined).Count ergibt 1, nicht 0. Das wuerde die Zusammenfassung verfaelschen.
    $boot14 = @(); $boot4 = @(); $bootPreAuth = @(); $bootLogon = @(); $bootLock = @()
    $bootWindows = @()
    if (-not $NoBootFilter) {
        $bootWindows = @(Get-BootWindows -MsBack $msBack -PostRollMinutes $BootWindowMinutes)
        if ($bootWindows.Count -gt 0) {
            $bw = ($bootWindows | ForEach-Object { $_.BootTime.ToString('dd.MM. HH:mm:ss') }) -join ', '
            Write-Host "  Boot-Fenster im Zeitraum: $($bootWindows.Count) ($bw) — Events darin gelten als by design" -ForegroundColor DarkGray
            Write-Host ""
        }
    }

    Write-Host "=== CHECK 1: TGT Requests (Event 4768) ===" -ForegroundColor Yellow
    Write-Host "  Using FilterXML (server-side filtering)..." -NoNewline

    # First: get ALL TGTs to see the distribution, then highlight RC4
    $xmlAllTgt = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $tgtEvents = @()
    try {
        $rawTgt = Get-WinEvent -FilterXml $xmlAllTgt -MaxEvents $MaxEvents -EA Stop
        Write-Host " $($rawTgt.Count) events (capped at $MaxEvents)" -ForegroundColor Green

        foreach ($evt in $rawTgt) {
            $x = [xml]$evt.ToXml()
            $account  = Get-XmlField $x 'TargetUserName'
            $domain   = Get-XmlField $x 'TargetDomainName'
            $encValue = Get-XmlField $x 'TicketEncryptionType'
            $ip       = Get-XmlField $x 'IpAddress'
            $status   = Get-XmlField $x 'Status'
            $encLabel = Get-EncLabel $encValue
            $isRC4    = $encLabel -match 'RC4'

            $tgtEvents += [PSCustomObject]@{
                Time=$evt.TimeCreated; Account=$account; Domain=$domain
                EncTypeValue=$encValue; EncTypeLabel=$encLabel; IsRC4=$isRC4
                ClientIP=$ip; Status=$status
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host " 0 events (audit not enabled?)" -ForegroundColor DarkGray
        } else { Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red }
    }

    if ($tgtEvents.Count -gt 0) {
        Write-Host ""
        Write-Host "  TGT Encryption Type Distribution:" -ForegroundColor White
        $tgtEvents | Group-Object EncTypeLabel | Sort-Object Count -Descending | ForEach-Object {
            $c = if ($_.Name -match 'RC4|DES') {'Red'} elseif ($_.Name -match 'AES') {'Green'} else {'Yellow'}
            $pct = [math]::Round(($_.Count / $tgtEvents.Count) * 100, 1)
            $label = "    {0} : {1} ({2}%)" -f $_.Name.PadRight(20), $_.Count.ToString().PadLeft(6), $pct
            Write-Host $label -ForegroundColor $c
        }

        $rc4TGTs = $tgtEvents | Where-Object { $_.IsRC4 }
        if ($rc4TGTs.Count -gt 0) {
            Write-Host ""
            Write-Host "  !!! $($rc4TGTs.Count) RC4 TGTs — WILL FAIL ON SERVER 2025 DC !!!" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Top RC4 accounts:" -ForegroundColor Yellow
            $rc4TGTs | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 15 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Red }
            Write-Host ""
            Write-Host "  Top RC4 client IPs:" -ForegroundColor Yellow
            $rc4TGTs | Group-Object ClientIP | Sort-Object Count -Descending | Select-Object -First 10 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(20)) : $($_.Count)" -ForegroundColor Red }
        } else {
            Write-Host ""; Write-Host "  No RC4 TGTs found." -ForegroundColor Green
        }
        Write-Host ""
    }

    #endregion

    #region --- Check 2: RC4 Service Tickets (Event 4769 — RC4 only via FilterXML) ---

    Write-Host "=== CHECK 2: RC4 Service Tickets (Event 4769) ===" -ForegroundColor Yellow
    Write-Host "  FilterXML: only RC4 tickets (server-side filter)..." -NoNewline

    # Only fetch RC4 service tickets — much faster than fetching all
    $xmlRC4Svc = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]] and *[EventData[Data[@Name=''TicketEncryptionType'']=''0x17'']]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $rc4SvcEvents = @()
    try {
        $rawSvc = Get-WinEvent -FilterXml $xmlRC4Svc -MaxEvents $MaxEvents -EA Stop
        Write-Host " $($rawSvc.Count) RC4 tickets!" -ForegroundColor Red

        foreach ($evt in $rawSvc) {
            $x = [xml]$evt.ToXml()
            $account = Get-XmlField $x 'TargetUserName'
            $service = Get-XmlField $x 'ServiceName'
            $ip      = Get-XmlField $x 'IpAddress'

            $rc4SvcEvents += [PSCustomObject]@{
                Time=$evt.TimeCreated; Account=$account; Service=$service
                EncTypeLabel='RC4-HMAC'; ClientIP=$ip
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host " 0 (good)" -ForegroundColor Green
        } else { Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red }
    }

    if ($rc4SvcEvents.Count -gt 0) {
        Write-Host ""
        Write-Host "  Top services receiving RC4 tickets:" -ForegroundColor Yellow
        $rc4SvcEvents | Group-Object Service | Sort-Object Count -Descending | Select-Object -First 15 |
            ForEach-Object { Write-Host "    $($_.Name.PadRight(45)) : $($_.Count)" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  Top accounts requesting RC4 service tickets:" -ForegroundColor Yellow
        $rc4SvcEvents | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 15 |
            ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Red }
        Write-Host ""
    }

    #endregion

    #region --- Check 3: Kerberos Errors (FilterXML) ---

    Write-Host "=== CHECK 3: Kerberos EncType Errors ===" -ForegroundColor Yellow

    # Event 14 — KDC_ERR_ETYPE_NOSUPP
    # Provider-Filter zwingend: ohne ihn matcht EventID 14 auch Wininit
    # ("Credential Guard (LsaIso.exe) configuration") und andere System-Log-Quellen.
    $xmlErr14 = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name=''Microsoft-Windows-Kerberos-Key-Distribution-Center''] and (EventID=14) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    Write-Host "  Event 14 (KDC_ERR_ETYPE_NOSUPP)..." -NoNewline
    $evt14 = @()
    try {
        $raw14 = @(Get-WinEvent -FilterXml $xmlErr14 -MaxEvents 50 -EA Stop)
        $boot14 = @($raw14 | Where-Object { Test-BootWindow $_.TimeCreated $bootWindows })
        $evt14  = @($raw14 | Where-Object { -not (Test-BootWindow $_.TimeCreated $bootWindows) })
        if ($evt14.Count -eq 0) {
            Write-Host " 0 (good)" -ForegroundColor Green
        } else {
            Write-Host " $($evt14.Count) errors!" -ForegroundColor Red
            foreach ($e in ($evt14 | Select-Object -First 3)) {
                Write-Host "    $($e.TimeCreated): $($e.Message.Substring(0, [math]::Min(120, $e.Message.Length)))..." -ForegroundColor Red
            }
            if ($evt14.Count -gt 3) { Write-Host "    ... and $($evt14.Count - 3) more" -ForegroundColor Red }
        }
        if ($boot14.Count -gt 0) {
            Write-Host "    ($($boot14.Count) im Boot-Fenster — by design, nicht gezaehlt)" -ForegroundColor DarkGray
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host " 0 (good)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # Event 4 — Client key error
    $xmlErr4 = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name=''Microsoft-Windows-Kerberos-Key-Distribution-Center''] and (EventID=4) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    Write-Host "  Event 4 (Client key not found)..." -NoNewline
    $evt4 = @()
    try {
        $raw4 = @(Get-WinEvent -FilterXml $xmlErr4 -MaxEvents 50 -EA Stop)
        $boot4 = @($raw4 | Where-Object { Test-BootWindow $_.TimeCreated $bootWindows })
        $evt4  = @($raw4 | Where-Object { -not (Test-BootWindow $_.TimeCreated $bootWindows) })
        if ($evt4.Count -eq 0) { Write-Host " 0 (good)" -ForegroundColor Green }
        else { Write-Host " $($evt4.Count) errors!" -ForegroundColor Red }
        if ($boot4.Count -gt 0) {
            Write-Host "    ($($boot4.Count) im Boot-Fenster — by design, nicht gezaehlt)" -ForegroundColor DarkGray
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host " 0 (good)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    Write-Host ""

    #endregion

    #region --- Check 3b: Ticket Renewals with RC4 (Event 4770) ---

    Write-Host "=== CHECK 3b: Ticket Renewals (Event 4770) ===" -ForegroundColor Yellow
    Write-Host "  RC4-Tickets die verlaengert werden leben laenger..." -NoNewline

    $xmlRenew = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4770) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]] and *[EventData[Data[@Name=''TicketEncryptionType'']=''0x17'']]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $rc4Renewals = @()
    try {
        $rawRenew = Get-WinEvent -FilterXml $xmlRenew -MaxEvents $MaxEvents -EA Stop
        Write-Host " $($rawRenew.Count) RC4 Renewals!" -ForegroundColor Red
        foreach ($evt in $rawRenew) {
            $x = [xml]$evt.ToXml()
            $rc4Renewals += [PSCustomObject]@{
                Time=$evt.TimeCreated
                Account=(Get-XmlField $x 'TargetUserName')
                Service=(Get-XmlField $x 'ServiceName')
                EncType='RC4-HMAC'
                ClientIP=(Get-XmlField $x 'IpAddress')
            }
        }
        if ($rc4Renewals.Count -gt 0) {
            Write-Host "    -> Event 4770: Ticket wurde verlaengert, RC4 bleibt aktiv bis Ablauf" -ForegroundColor DarkGray
            Write-Host "  Top Accounts mit RC4-Renewal:" -ForegroundColor Yellow
            $rc4Renewals | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Red }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }
    Write-Host ""

    #endregion

    #region --- Check 3c: Kerberos Pre-Auth Failed (Event 4771) ---

    Write-Host "=== CHECK 3c: Kerberos Pre-Auth Fehler (Event 4771) ===" -ForegroundColor Yellow
    Write-Host "  Beginn der Fallback-Kette: Kerberos scheitert, NTLM folgt..." -NoNewline

    $xmlPreAuth = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4771) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $preAuthFails = @()
    try {
        $rawPreAuthAll = @(Get-WinEvent -FilterXml $xmlPreAuth -MaxEvents $MaxEvents -EA Stop)
        $bootPreAuth = @($rawPreAuthAll | Where-Object { Test-BootWindow $_.TimeCreated $bootWindows })
        $rawPreAuth  = @($rawPreAuthAll | Where-Object { -not (Test-BootWindow $_.TimeCreated $bootWindows) })
        Write-Host " $($rawPreAuth.Count) Fehler" -ForegroundColor $(if ($rawPreAuth.Count -gt 50) {'Red'} elseif ($rawPreAuth.Count -gt 0) {'Yellow'} else {'Green'})
        if ($bootPreAuth.Count -gt 0) {
            Write-Host "    ($($bootPreAuth.Count) im Boot-Fenster — Dienste-Neustart, by design, nicht gezaehlt)" -ForegroundColor DarkGray
        }
        foreach ($evt in $rawPreAuth) {
            $x = [xml]$evt.ToXml()
            $preAuthFails += [PSCustomObject]@{
                Time=$evt.TimeCreated
                Account=(Get-XmlField $x 'TargetUserName')
                Status=(Get-XmlField $x 'Status')
                ClientIP=(Get-XmlField $x 'IpAddress')
            }
        }
        if ($preAuthFails.Count -gt 0) {
            Write-Host "    -> Event 4771: Kerberos Pre-Auth gescheitert, Client versucht ggf. NTLM-Fallback" -ForegroundColor DarkGray
            # Status codes
            $statusGroups = $preAuthFails | Group-Object Status | Sort-Object Count -Descending
            Write-Host "  Status-Verteilung:" -ForegroundColor Yellow
            foreach ($sg in $statusGroups) {
                $statusLabel = switch ($sg.Name) {
                    '0x12' { 'Pre-Auth Required (normal)' }
                    '0x17' { 'Password expired' }
                    '0x18' { 'Pre-Auth failed (falsches PW)' }
                    '0x25' { 'Clock skew' }
                    default { "Code $($sg.Name)" }
                }
                $c = if ($sg.Name -eq '0x18') {'Red'} elseif ($sg.Name -eq '0x12') {'DarkGray'} else {'Yellow'}
                Write-Host "    $($statusLabel.PadRight(40)) : $($sg.Count)" -ForegroundColor $c
            }
            # Top accounts with 0x18 (wrong password - potential fallback lockout)
            $wrongPw = $preAuthFails | Where-Object { $_.Status -eq '0x18' }
            if ($wrongPw.Count -gt 0) {
                Write-Host ""
                Write-Host "  !!! $($wrongPw.Count) fehlgeschlagene Passwort-Versuche (0x18) !!!" -ForegroundColor Red
                Write-Host "  Moeglicher NTLM-Fallback nach Kerberos-Fehler → Lockout-Risiko" -ForegroundColor Red
                Write-Host "  Top Accounts:" -ForegroundColor Yellow
                $wrongPw | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 |
                    ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Red }
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }
    Write-Host ""

    #endregion

    #region --- Check 5: Fallback-Kette — NTLM Failures + Lockouts (4625 + 4740) ---

    Write-Host "=== CHECK 5: Fallback-Kette — NTLM Fehler + Lockouts ===" -ForegroundColor Yellow

    # Event 4625 — Failed Logon (NTLM fallback)
    Write-Host "  Event 4625 (Failed Logon / NTLM)..." -NoNewline

    $xmlLogonFail = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $logonFails = @()
    try {
        $rawLogonAll  = @(Get-WinEvent -FilterXml $xmlLogonFail -MaxEvents $MaxEvents -EA Stop)
        $bootLogon    = @($rawLogonAll | Where-Object { Test-BootWindow $_.TimeCreated $bootWindows })
        $rawLogonFail = @($rawLogonAll | Where-Object { -not (Test-BootWindow $_.TimeCreated $bootWindows) })
        Write-Host " $($rawLogonFail.Count)" -ForegroundColor $(if ($rawLogonFail.Count -gt 100) {'Red'} elseif ($rawLogonFail.Count -gt 0) {'Yellow'} else {'Green'})
        if ($bootLogon.Count -gt 0) {
            Write-Host "    ($($bootLogon.Count) im Boot-Fenster — by design, nicht gezaehlt)" -ForegroundColor DarkGray
        }
        foreach ($evt in $rawLogonFail) {
            $x = [xml]$evt.ToXml()
            $logonFails += [PSCustomObject]@{
                Time=$evt.TimeCreated
                Account=(Get-XmlField $x 'TargetUserName')
                Domain=(Get-XmlField $x 'TargetDomainName')
                LogonType=(Get-XmlField $x 'LogonType')
                AuthPackage=(Get-XmlField $x 'AuthenticationPackageName')
                SourceIP=(Get-XmlField $x 'IpAddress')
                Workstation=(Get-XmlField $x 'WorkstationName')
                Status=(Get-XmlField $x 'Status')
                SubStatus=(Get-XmlField $x 'SubStatus')
            }
        }
        if ($logonFails.Count -gt 0) {
            Write-Host "    -> Event 4625: Fehlgeschlagener Login — nach Kerberos-Fehler ggf. NTLM-Fallback" -ForegroundColor DarkGray
            # Auth Package Distribution
            $authPkgs = $logonFails | Group-Object AuthPackage | Sort-Object Count -Descending
            Write-Host "  Auth-Paket Verteilung:" -ForegroundColor Yellow
            foreach ($ap in $authPkgs) {
                $c = if ($ap.Name -match 'NTLM') {'Yellow'} elseif ($ap.Name -match 'Kerberos') {'Cyan'} else {'White'}
                Write-Host "    $($ap.Name.PadRight(20)) : $($ap.Count)" -ForegroundColor $c
            }
            # Top source workstations
            $topSources = $logonFails | Group-Object Workstation | Sort-Object Count -Descending | Select-Object -First 10
            Write-Host "  Top Quellen (Workstation):" -ForegroundColor Yellow
            foreach ($ts2 in $topSources) {
                Write-Host "    $($ts2.Name.PadRight(30)) : $($ts2.Count)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }
    Write-Host ""

    # Event 4740 — Account Lockout
    Write-Host "  Event 4740 (Account Lockout)..." -NoNewline

    $xmlLockout = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $lockouts = @()
    try {
        # Lockouts werden NICHT gefiltert — eine Kontosperrung ist nie "by design".
        # Sie wird nur markiert wenn sie ins Boot-Fenster faellt (Kontext fuer die Ursache).
        $rawLockout = @(Get-WinEvent -FilterXml $xmlLockout -MaxEvents $MaxEvents -EA Stop)
        Write-Host " $($rawLockout.Count)" -ForegroundColor $(if ($rawLockout.Count -gt 20) {'Red'} elseif ($rawLockout.Count -gt 0) {'Yellow'} else {'Green'})
        $bootLock = @($rawLockout | Where-Object { Test-BootWindow $_.TimeCreated $bootWindows })
        if ($bootLock.Count -gt 0) {
            Write-Host "    ($($bootLock.Count) davon im Boot-Fenster — Ursache pruefen, wird trotzdem gezaehlt)" -ForegroundColor Yellow
        }
        foreach ($evt in $rawLockout) {
            $x = [xml]$evt.ToXml()
            $lockouts += [PSCustomObject]@{
                Time=$evt.TimeCreated
                Account=(Get-XmlField $x 'TargetUserName')
                CallerComputer=(Get-XmlField $x 'SubjectUserName')
            }
        }
        if ($lockouts.Count -gt 0) {
            Write-Host "    -> Event 4740: Lockout — wenn kurz nach Kerberos-/NTLM-Fehlern = Fallback-Kette" -ForegroundColor DarkGray
            Write-Host "  Top gesperrte Accounts:" -ForegroundColor Yellow
            $lockouts | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Yellow }
            Write-Host "  Top Caller (Quelle der Sperrung):" -ForegroundColor Yellow
            $lockouts | Group-Object CallerComputer | Sort-Object Count -Descending | Select-Object -First 10 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Yellow }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # Korrelation: Lockouts die innerhalb 60s nach Kerberos Pre-Auth Fehler kommen
    if ($lockouts.Count -gt 0 -and $preAuthFails.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- KORRELATION: Lockouts nach Kerberos-Fehler (60s Fenster) ---" -ForegroundColor Cyan
        $correlated = @()
        foreach ($lo in $lockouts) {
            $match = $preAuthFails | Where-Object {
                $_.Account -eq $lo.Account -and
                [math]::Abs(($_.Time - $lo.Time).TotalSeconds) -le 60
            }
            if ($match) {
                $correlated += [PSCustomObject]@{
                    Account=$lo.Account
                    LockoutTime=$lo.Time
                    KerbFailTime=$match[0].Time
                    KerbStatus=$match[0].Status
                    DeltaSeconds=[math]::Round(($lo.Time - $match[0].Time).TotalSeconds)
                    CallerComputer=$lo.CallerComputer
                }
            }
        }
        if ($correlated.Count -gt 0) {
            Write-Host "  $($correlated.Count) Lockouts mit Kerberos-Fehler im 60s-Fenster!" -ForegroundColor Red
            Write-Host "  Das deutet auf Fallback-Kette hin: Kerberos scheitert → NTLM → Lockout" -ForegroundColor Red
            foreach ($c in ($correlated | Select-Object -First 5)) {
                Write-Host "    $($c.Account.PadRight(25)) Kerb-Fail: $($c.KerbFailTime.ToString('HH:mm:ss')) → Lockout: $($c.LockoutTime.ToString('HH:mm:ss')) (${$c.DeltaSeconds}s) Caller: $($c.CallerComputer)" -ForegroundColor Red
            }
        } else {
            Write-Host "  Keine Korrelation gefunden — Lockouts sind unabhaengig von Kerberos-Fehlern." -ForegroundColor Green
        }
    }
    Write-Host ""

    #endregion

    #region --- Check 6: LDAP Signing (Directory Service 2886/2887/2889) ---

    Write-Host "=== CHECK 6: LDAP Signing ===" -ForegroundColor Yellow

    # Event 2887 — Count of unsigned binds in last 24h
    Write-Host "  Event 2887 (Unsigned Binds Zusammenfassung)..." -NoNewline

    $xml2887 = '<QueryList><Query Id="0" Path="Directory Service"><Select Path="Directory Service">*[System[(EventID=2887) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    try {
        $raw2887 = Get-WinEvent -FilterXml $xml2887 -MaxEvents 5 -EA Stop
        Write-Host " $($raw2887.Count) Eintraege" -ForegroundColor Yellow
        foreach ($e in $raw2887) {
            Write-Host "    $($e.TimeCreated): $($e.Message.Substring(0, [math]::Min(150, $e.Message.Length)))..." -ForegroundColor Yellow
        }
        Write-Host "    -> Reg: HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity" -ForegroundColor DarkGray
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut — oder Log nicht vorhanden)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # Event 2889 — Per-client unsigned bind detail
    Write-Host "  Event 2889 (Unsigned Bind pro Client)..." -NoNewline

    $xml2889 = '<QueryList><Query Id="0" Path="Directory Service"><Select Path="Directory Service">*[System[(EventID=2889) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    $unsignedBinds = @()
    try {
        $raw2889 = Get-WinEvent -FilterXml $xml2889 -MaxEvents $MaxEvents -EA Stop
        Write-Host " $($raw2889.Count)" -ForegroundColor $(if ($raw2889.Count -gt 50) {'Red'} elseif ($raw2889.Count -gt 0) {'Yellow'} else {'Green'})
        foreach ($evt in $raw2889) {
            $x = [xml]$evt.ToXml()
            $unsignedBinds += [PSCustomObject]@{
                Time=$evt.TimeCreated
                ClientIP=(Get-XmlField $x 'param1')
                Account=(Get-XmlField $x 'param2')
                BindType=(Get-XmlField $x 'param3')
            }
        }
        if ($unsignedBinds.Count -gt 0) {
            Write-Host "    -> Event 2889: Clients mit unsigniertem LDAP-Bind — brechen bei LDAP Signing Enforcement" -ForegroundColor DarkGray
            Write-Host "  Top Clients mit unsigned Bind:" -ForegroundColor Yellow
            $unsignedBinds | Group-Object ClientIP | Sort-Object Count -Descending | Select-Object -First 10 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(25)) : $($_.Count)" -ForegroundColor Yellow }
            Write-Host "  Top Accounts:" -ForegroundColor Yellow
            $unsignedBinds | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 |
                ForEach-Object { Write-Host "    $($_.Name.PadRight(35)) : $($_.Count)" -ForegroundColor Yellow }
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    # Event 3039 — Channel Binding not supported
    Write-Host "  Event 3039 (Channel Binding fehlt)..." -NoNewline

    $xml3039 = '<QueryList><Query Id="0" Path="Directory Service"><Select Path="Directory Service">*[System[(EventID=3039) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

    try {
        $raw3039 = Get-WinEvent -FilterXml $xml3039 -MaxEvents 50 -EA Stop
        Write-Host " $($raw3039.Count)" -ForegroundColor $(if ($raw3039.Count -gt 0) {'Yellow'} else {'Green'})
    }
    catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            Write-Host " 0 (gut)" -ForegroundColor Green
        } else { Write-Host " $($_.Exception.Message)" -ForegroundColor DarkGray }
    }

    Write-Host ""

    #endregion

    #region --- Check 7: AD Account Encryption Types ---

    Write-Host "=== CHECK 7: AD Accounts mit RC4 ===" -ForegroundColor Yellow

    try {
        Get-Command Get-ADComputer -EA Stop | Out-Null

        Write-Host "  Computer accounts with RC4..." -NoNewline
        $rc4Comp = @(Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
            Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 })
        Write-Host " $($rc4Comp.Count)" -ForegroundColor $(if ($rc4Comp.Count -gt 0) {'Yellow'} else {'Green'})

        Write-Host "  RC4-ONLY computers (will break)..." -NoNewline
        $rc4Only = @($rc4Comp | Where-Object { -not ($_.'msDS-SupportedEncryptionTypes' -band 0x18) })
        Write-Host " $($rc4Only.Count)" -ForegroundColor $(if ($rc4Only.Count -gt 0) {'Red'} else {'Green'})

        Write-Host "  gMSAs with RC4..." -NoNewline
        $rc4gMSA = @(Get-ADServiceAccount -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
            Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 })
        Write-Host " $($rc4gMSA.Count)" -ForegroundColor $(if ($rc4gMSA.Count -gt 0) {'Yellow'} else {'Green'})

        Write-Host "  Trusts without AES..." -NoNewline
        $domDN = (Get-ADDomain).DistinguishedName
        $trusts = @(Get-ADObject -SearchBase "CN=System,$domDN" -LDAPFilter '(objectClass=trustedDomain)' `
            -Properties 'msDS-SupportedEncryptionTypes')
        $rc4Trusts = @($trusts | Where-Object {
            $e = $_.'msDS-SupportedEncryptionTypes'; $null -eq $e -or $e -eq 0 -or ($e -band 0x4 -and -not ($e -band 0x18))
        })
        Write-Host " $($rc4Trusts.Count) / $($trusts.Count)" -ForegroundColor $(if ($rc4Trusts.Count -gt 0) {'Red'} else {'Green'})
    }
    catch {
        Write-Host "  AD module not available — skipped" -ForegroundColor DarkGray
    }

    Write-Host ""

    #endregion

    #region --- Summary & Export ---

    $rc4TgtCount = ($tgtEvents | Where-Object { $_.IsRC4 }).Count
    $rc4SvcCount = $rc4SvcEvents.Count
    $rc4RenewCount = $rc4Renewals.Count
    $errCount    = $evt14.Count + $evt4.Count
    $preAuthCount = $preAuthFails.Count
    $preAuth18   = ($preAuthFails | Where-Object { $_.Status -eq '0x18' }).Count
    $logonFailCount = $logonFails.Count
    $lockoutCount = $lockouts.Count
    $correlatedCount = if ($correlated) { $correlated.Count } else { 0 }
    $unsignedCount = $unsignedBinds.Count

    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  ZUSAMMENFASSUNG — $(hostname) — letzte $Hours Stunden" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  --- Kerberos RC4 ---" -ForegroundColor White
    Write-Host "  TGTs geprueft           : $($tgtEvents.Count) (max $MaxEvents)" -ForegroundColor White
    Write-Host "  TGTs mit RC4            : $rc4TgtCount" -ForegroundColor $(if ($rc4TgtCount -gt 0) {'Red'} else {'Green'})
    Write-Host "  RC4 Service Tickets     : $rc4SvcCount" -ForegroundColor $(if ($rc4SvcCount -gt 0) {'Red'} else {'Green'})
    Write-Host "  RC4 Ticket Renewals     : $rc4RenewCount" -ForegroundColor $(if ($rc4RenewCount -gt 0) {'Red'} else {'Green'})
    Write-Host "  Kerberos EncType Fehler : $errCount" -ForegroundColor $(if ($errCount -gt 0) {'Red'} else {'Green'})
    $bootTotal = (@($boot14).Count + @($boot4).Count + @($bootPreAuth).Count + @($bootLogon).Count)
    if ($bootTotal -gt 0) {
        Write-Host "  davon Boot-Rauschen      : $bootTotal (nicht gezaehlt)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  --- Fallback-Kette ---" -ForegroundColor White
    Write-Host "  Pre-Auth Fehler (4771)  : $preAuthCount" -ForegroundColor $(if ($preAuthCount -gt 50) {'Red'} elseif ($preAuthCount -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  davon falsches PW (0x18): $preAuth18" -ForegroundColor $(if ($preAuth18 -gt 0) {'Red'} else {'Green'})
    Write-Host "  Failed Logons (4625)    : $logonFailCount" -ForegroundColor $(if ($logonFailCount -gt 100) {'Red'} elseif ($logonFailCount -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  Account Lockouts (4740) : $lockoutCount" -ForegroundColor $(if ($lockoutCount -gt 20) {'Red'} elseif ($lockoutCount -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  Korreliert (Kerb→Lock)  : $correlatedCount" -ForegroundColor $(if ($correlatedCount -gt 0) {'Red'} else {'Green'})
    Write-Host ""
    Write-Host "  --- LDAP Signing ---" -ForegroundColor White
    Write-Host "  Unsigned LDAP Binds     : $unsignedCount" -ForegroundColor $(if ($unsignedCount -gt 50) {'Red'} elseif ($unsignedCount -gt 0) {'Yellow'} else {'Green'})
    Write-Host ""

    if ($rc4TgtCount -gt 0 -or $rc4SvcCount -gt 0) {
        Write-Host "  !!! RC4 WIRD IN DIESER UMGEBUNG AKTIV VERWENDET !!!" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Server 2025 DCs stellen keine RC4 TGTs mehr aus (by design)." -ForegroundColor Red
        Write-Host "  Betroffene Accounts muessen auf AES migriert werden." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Fix: Accounts von RC4 (Wert 28) auf AES-only (Wert 24) umstellen." -ForegroundColor Yellow
        Write-Host "  Ref: https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos" -ForegroundColor DarkGray
    } elseif ($errCount -gt 0) {
        Write-Host "  Keine RC4-Tickets gefunden, aber Kerberos-Fehler vorhanden." -ForegroundColor Yellow
        Write-Host "  Der 2025 DC blockiert moeglicherweise bereits RC4. Event 14 pruefen." -ForegroundColor Yellow
    } else {
        Write-Host "  Keine RC4-Nutzung erkannt." -ForegroundColor Green
        Write-Host "  Entweder wird RC4 nicht verwendet, oder Kerberos-Auditing ist nicht aktiviert." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Auditing aktivieren:" -ForegroundColor Yellow
        Write-Host '  auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable' -ForegroundColor Yellow
        Write-Host '  auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable' -ForegroundColor Yellow
    }

    Write-Host ""

    # Export CSVs
    if ($tgtEvents.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_TGT_${ts}.csv"
        $tgtEvents | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  TGT events     : $p" -ForegroundColor Green
    }
    if ($rc4SvcEvents.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_SvcTickets_${ts}.csv"
        $rc4SvcEvents | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  RC4 SvcTickets : $p" -ForegroundColor Green
    }
    if ($rc4TgtCount -gt 0 -or $rc4SvcCount -gt 0) {
        $p = "${ExportPath}\RC4_Proof_URGENT_${ts}.csv"
        $urgent = @()
        $urgent += $tgtEvents | Where-Object { $_.IsRC4 } | Group-Object Account |
            ForEach-Object { [PSCustomObject]@{
                Type='TGT'; Account=$_.Name; RC4Count=$_.Count
                Fix="Reset password or Set-ADComputer -KerberosEncryptionType AES128,AES256"
            }}
        $urgent += $rc4SvcEvents | Group-Object Service |
            ForEach-Object { [PSCustomObject]@{
                Type='ServiceTicket'; Account=$_.Name; RC4Count=$_.Count
                Fix="Set msDS-SupportedEncryptionTypes to 24 (AES-only)"
            }}
        $urgent | Sort-Object RC4Count -Descending | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  URGENT fixes   : $p" -ForegroundColor Red
    }
    if ($rc4Renewals.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_Renewals_${ts}.csv"
        $rc4Renewals | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  RC4 Renewals   : $p" -ForegroundColor Red
    }
    if ($preAuthFails.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_PreAuth_${ts}.csv"
        $preAuthFails | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Pre-Auth Fails : $p" -ForegroundColor Yellow
    }
    if ($logonFails.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_LogonFails_${ts}.csv"
        $logonFails | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Logon Fails    : $p" -ForegroundColor Yellow
    }
    if ($lockouts.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_Lockouts_${ts}.csv"
        $lockouts | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Lockouts       : $p" -ForegroundColor Yellow
    }
    if ($correlatedCount -gt 0) {
        $p = "${ExportPath}\RC4_Proof_Korrelation_${ts}.csv"
        $correlated | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Korrelation    : $p" -ForegroundColor Red
    }
    if ($unsignedBinds.Count -gt 0) {
        $p = "${ExportPath}\RC4_Proof_UnsignedLDAP_${ts}.csv"
        $unsignedBinds | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Unsigned LDAP  : $p" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  RC4 Pruefung abgeschlossen. Vor Server 2025 Installation beheben." -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
#endregion

#region ============ MODUS: DISCOVER ============
function Invoke-ModeDiscover {
    Set-StrictMode -Version 2   # wie im Original
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $msBack = $Hours * 3600 * 1000

    # Domain name without TLD for filename
    $domainFQDN = $env:USERDNSDOMAIN
    if (-not $domainFQDN) {
        try { $domainFQDN = (Get-ADDomain -EA Stop).DNSRoot } catch { $domainFQDN = 'UNKNOWN' }
    }
    $domainShort = ($domainFQDN -split '\.')[0]
    $reportDir = Join-Path $ReportPath "RC4_${domainShort}_${ts}"

    if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
    #region ============ MAIN ============

    # Execution guard: -ImportOnly or dot-sourcing detection
    $script:_IsDotSourced = $false
    try {
        if ($MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -match '^\.\s') {
            $script:_IsDotSourced = $true
        }
    } catch {}

    if ($ImportOnly) {
        Write-Host "  Funktionen geladen (-ImportOnly). Kein Scan." -ForegroundColor Cyan
        Write-Host "  Verfuegbare Funktionen:" -ForegroundColor DarkGray
        Write-Host "    Get-CitrixInfrastructure    Get-IgelDevices" -ForegroundColor DarkGray
        Write-Host "    Get-NonWindowsDevices       Get-DelegationAccounts" -ForegroundColor DarkGray
        Write-Host "    Get-KerberosGPOPolicy       Get-RC4TicketsBySystem" -ForegroundColor DarkGray
        Write-Host "    Write-Kreuzpruefung         Import-PreviousReport" -ForegroundColor DarkGray
        Write-Host "    Export-ExcelReport          Export-ToCsv" -ForegroundColor DarkGray
        Write-Host "    Get-Bewertung               Get-DelegationBewertung" -ForegroundColor DarkGray
        Write-Host "    Get-EncCategory             Get-EncLabel  SafeCount" -ForegroundColor DarkGray
    }
    elseif (-not $script:_IsDotSourced) {
    # === SCAN/REASSESS EXECUTION (only when run directly) ===

    if ($ReassessFrom) {
        # =============================================
        # REASSESS MODE: Load from previous CSVs
        # =============================================
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Magenta
        Write-Host "  RC4 Environment Discovery v1.7 — REASSESSMENT" -ForegroundColor Magenta
        Write-Host "  Quelle: $ReassessFrom" -ForegroundColor Magenta
        Write-Host "=================================================================" -ForegroundColor Magenta

        $prev = Import-PreviousReport -Path $ReassessFrom
        if (-not $prev) {
            Write-Host "`n  Abbruch — keine Daten geladen." -ForegroundColor Red
            return
        }

        # Use imported data
        $discovery = $prev.Discovery
        $events    = $prev.Events
        $gpo       = $prev.GPO

        $citrix = @($discovery.Citrix)
        $igel   = @($discovery.Igel)
        $nonwin = @($discovery.NonWindows)
        $deleg  = @($discovery.Delegation)

        # Detect domain from source path
        $folderName = Split-Path $ReassessFrom -Leaf
        if ($folderName -match 'RC4_([^_]+)_') { $domainShort = $Matches[1] }
        if (-not $domainFQDN -or $domainFQDN -eq 'UNKNOWN') { $domainFQDN = $domainShort }

        # Reassess report directory
        $reportDir = Join-Path $ReportPath "RC4_${domainShort}_Reassess_${ts}"
        if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }

        # Summary
        $allSystems = @() + $citrix + $igel + $nonwin
        $rc4Risk = @($allSystems | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
        $delegRC4 = @($deleg | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })

        Write-Host "`n=== IMPORTIERTE DATEN ===" -ForegroundColor Cyan
        Write-Status "Systeme gesamt" "$((SafeCount $allSystems))"
        Write-Status "davon mit RC4/DES" "$((SafeCount $rc4Risk))" $(if ((SafeCount $rc4Risk) -gt 0) {'Red'} else {'Green'})
        Write-Status "Delegation-Accounts mit RC4/DES" "$((SafeCount $delegRC4))" $(if ((SafeCount $delegRC4) -gt 0) {'Red'} else {'Green'})
        Write-Status "RC4 Tickets" "$((SafeCount $events.RC4Tickets))" $(if ((SafeCount $events.RC4Tickets) -gt 0) {'Red'} else {'Green'})
        Write-Status "PreAuth Fehler" "$((SafeCount $events.PreAuthFails))"
        Write-Status "Lockouts" "$((SafeCount $events.Lockouts))"
        Write-Status "Korrelierte Lockouts" "$((SafeCount $events.Correlated))" $(if ((SafeCount $events.Correlated) -gt 0) {'Red'} else {'Green'})

        # Cross-check (the whole point of reassessment)
        $crossCheck = Write-Kreuzpruefung -Discovery $discovery -Events $events -GPO $gpo `
            -AllSystems $allSystems -RC4Risk $rc4Risk -DelegRC4 $delegRC4

        # Export reassessment
        Write-Host "`n=== EXPORT (Reassessment) ===" -ForegroundColor Cyan
        $report = Export-ExcelReport -Discovery $discovery -Events $events -GPO $gpo -Path $reportDir

        if ((SafeCount $crossCheck) -gt 0) {
            $xlPath = Join-Path $reportDir "RC4_${domainShort}_Report.xlsx"
            $hasExcel = $false
            try { Import-Module ImportExcel -EA Stop; $hasExcel = $true } catch {}
            if ($hasExcel) {
                $crossCheck | Select-Object Nr, Typ, Bereich, Befund, Bewertung, Bedingung |
                    Export-Excel -Path $xlPath -WorksheetName 'Kreuzpruefung' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                        New-ConditionalText 'Fehler'      -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
                        New-ConditionalText 'Warnung'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
                        New-ConditionalText 'Information' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
                    )
                Write-Host "  Excel-Tab    : Kreuzpruefung" -ForegroundColor Green
            }
            $crossCheck | Select-Object Nr, Typ, Bereich, Befund, Bewertung, Bedingung |
                Export-Csv (Join-Path $reportDir 'Kreuzpruefung.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
            Write-Host "  CSV          : Kreuzpruefung.csv" -ForegroundColor Green
        }

        $zip = Compress-Report -FolderPath $reportDir

        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Magenta
        Write-Host "  Reassessment abgeschlossen." -ForegroundColor Magenta
        Write-Host "  Quelle  : $ReassessFrom" -ForegroundColor White
        Write-Host "  Report  : $reportDir" -ForegroundColor White
        if ($zip) { Write-Host "  ZIP     : $zip" -ForegroundColor White }
        Write-Host "=================================================================" -ForegroundColor Magenta
        Write-Host ""
        return
    }

    # =============================================
    # NORMAL MODE: Full scan
    # =============================================

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  RC4 Environment Discovery v1.7" -ForegroundColor Cyan
    Write-Host "  Domaene: $domainFQDN ($domainShort)" -ForegroundColor Cyan
    Write-Host "  Zeitraum: letzte $Hours Stunden auf $(hostname)" -ForegroundColor Cyan
    Write-Host "  Report: $reportDir" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    # Phase 1: AD Discovery
    $citrix = Get-CitrixInfrastructure
    $igel = Get-IgelDevices
    $nonwin = Get-NonWindowsDevices
    $deleg = Get-DelegationAccounts
    $gpo = Get-KerberosGPOPolicy

    $discovery = @{
        Citrix = $citrix
        Igel = $igel
        NonWindows = $nonwin
        Delegation = $deleg
    }

    # Summary
    Write-Host "`n=== DISCOVERY ZUSAMMENFASSUNG ===" -ForegroundColor Cyan
    $allSystems = @() + $citrix + $igel + $nonwin
    $rc4Risk = @($allSystems | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
    $delegRC4 = @($deleg | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })

    Write-Status "Systeme gesamt" "$((SafeCount $allSystems))"
    Write-Status "davon mit RC4/DES" "$((SafeCount $rc4Risk))" $(if ((SafeCount $rc4Risk) -gt 0) {'Red'} else {'Green'})
    Write-Status "Delegation-Accounts mit RC4/DES" "$((SafeCount $delegRC4))" $(if ((SafeCount $delegRC4) -gt 0) {'Red'} else {'Green'})

    # Phase 2: Events
    $events = $null
    $kdcsvc = $null
    $ntlmInfo = $null
    if (-not $SkipEvents) {
        $knownNames = ($allSystems | Select-Object -ExpandProperty Name) + ($deleg | Select-Object -ExpandProperty Name)
        $events = Get-RC4TicketsBySystem -MsBack $msBack -Max $MaxEvents -KnownSystems $knownNames
        $kdcsvc = Get-KdcsvcAuditEvents -Max $MaxEvents
        $ntlmInfo = Get-NTLMv1Usage -MsBack $msBack -Max $MaxEvents
    }

    # Phase 3: Cross-check
    $crossCheck = Write-Kreuzpruefung -Discovery $discovery -Events $events -GPO $gpo `
        -AllSystems $allSystems -RC4Risk $rc4Risk -DelegRC4 $delegRC4

    # Additional findings from KDCSVC and NTLMv1 (append to crossCheck)
    if ($kdcsvc -and (SafeCount $kdcsvc.Events) -gt 0) {
        $crossCheck += [PSCustomObject]@{
            Nr=9; Typ='Fehler'; Bereich='KDCSVC Audit Events (Januar 2026 CU)'
            Befund="$((SafeCount $kdcsvc.Events)) KDCSVC Events im System Log. Diese zeigen Accounts/Dienste die im April 2026 fehlschlagen."
            Bewertung="Aktiv — der neue Microsoft Audit hat RC4-Abhaengigkeiten erkannt. Event 201/202/206/207 = Warnung. Event 203/204/209 = bereits blockiert."
            Bedingung="Diese Accounts schlagen ab dem April-2026-Patchday fehl wenn nicht vorher auf AES umgestellt."
        }
    }
    elseif ($kdcsvc -and (SafeCount $kdcsvc.Events) -eq 0 -and $kdcsvc.CUInstalled) {
        $crossCheck += [PSCustomObject]@{
            Nr=9; Typ='Information'; Bereich='KDCSVC Audit Events (Januar 2026 CU)'
            Befund="0 KDCSVC Events. Der Microsoft Audit erkennt keine RC4-Abhaengigkeiten."
            Bewertung="Kein RC4-Risiko durch den neuen Audit erkannt. Die Umgebung ist fuer das April-Update vorbereitet."
            Bedingung="Keine."
        }
    }
    elseif ($kdcsvc -and -not $kdcsvc.CUInstalled) {
        $crossCheck += [PSCustomObject]@{
            Nr=9; Typ='Warnung'; Bereich='KDCSVC Audit Events'
            Befund="Januar 2026 CU nicht installiert oder KDCSVC Provider nicht verfuegbar."
            Bewertung="Schlafend — ohne das Januar CU fehlen die neuen Audit Events 201-209. Erst nach Installation zeigt der KDC welche Accounts im April fehlschlagen."
            Bedingung="Januar 2026 CU auf allen DCs installieren."
        }
    }

    if ($ntlmInfo -and $ntlmInfo.V1Count -gt 0) {
        $v1Top = ($ntlmInfo.V1Accounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { ($_.Key -split '\|')[0] }) -join ', '
        $crossCheck += [PSCustomObject]@{
            Nr=10; Typ='Fehler'; Bereich='NTLMv1 Anmeldungen'
            Befund="$($ntlmInfo.V1Count) NTLMv1-Anmeldungen erkannt. NTLMv1 ist kryptographisch gebrochen (Mandiant Rainbow Tables)."
            Bewertung="Aktiv — NTLMv1 ermoeglicht sofortige Credential-Kompromittierung. NTLMv2 ist deprecated aber noch nicht gebrochen. NTLMv1 muss sofort per GPO blockiert werden."
            Bedingung="Top Accounts: $v1Top. GPO: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM and NTLM."
        }
    }
    elseif ($ntlmInfo -and $ntlmInfo.V2Count -gt 0) {
        $crossCheck += [PSCustomObject]@{
            Nr=10; Typ='Information'; Bereich='NTLM Anmeldungen'
            Befund="$($ntlmInfo.V2Count) NTLMv2-Anmeldungen, 0 NTLMv1. NTLMv2 ist deprecated (Microsoft, Januar 2026)."
            Bewertung="NTLMv2 ist kryptographisch nicht gebrochen aber deprecated. In der naechsten Windows-Version wird NTLM standardmaessig deaktiviert. Kerberos ist der Zielzustand."
            Bedingung="Mittelfristig: NTLM-Abhaengigkeiten identifizieren und auf Kerberos umstellen."
        }
    }

    # Phase 4: Export
    Write-Host "`n=== EXPORT ===" -ForegroundColor Cyan
    $report = Export-ExcelReport -Discovery $discovery -Events $events -GPO $gpo -Path $reportDir

    # Export cross-check findings
    if ((SafeCount $crossCheck) -gt 0) {
        $xlPath = Join-Path $reportDir "RC4_${domainShort}_Report.xlsx"
        $hasExcel = $false
        try { Import-Module ImportExcel -EA Stop; $hasExcel = $true } catch {}
        if ($hasExcel) {
            $crossCheck | Select-Object Nr, Typ, Bereich, Befund, Bewertung, Bedingung |
                Export-Excel -Path $xlPath -WorksheetName 'Kreuzpruefung' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $(
                    New-ConditionalText 'Fehler'      -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
                    New-ConditionalText 'Warnung'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
                    New-ConditionalText 'Information' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
                )
            Write-Host "  Excel-Tab    : Kreuzpruefung" -ForegroundColor Green
        }
        $crossCheck | Select-Object Nr, Typ, Bereich, Befund, Bewertung, Bedingung |
            Export-Csv (Join-Path $reportDir 'Kreuzpruefung.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV          : Kreuzpruefung.csv" -ForegroundColor Green
    }

    # KDCSVC Events CSV
    if ($kdcsvc -and (SafeCount $kdcsvc.Events) -gt 0) {
        $kdcsvc.Events | Export-Csv (Join-Path $reportDir 'KDCSVC_Audit.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV          : KDCSVC_Audit.csv ($((SafeCount $kdcsvc.Events)) Events)" -ForegroundColor Green
    }

    # NTLMv1 CSV
    if ($ntlmInfo -and $ntlmInfo.V1Count -gt 0) {
        $ntlmInfo.V1Accounts.GetEnumerator() | ForEach-Object {
            $parts = $_.Key -split '\|'
            [PSCustomObject]@{ Account=$parts[0]; Workstation=$parts[1]; Count=$_.Value; Version='NTLMv1'; Risiko='Fehler — kryptographisch gebrochen' }
        } | Sort-Object Count -Descending |
            Export-Csv (Join-Path $reportDir 'NTLMv1_Usage.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV          : NTLMv1_Usage.csv ($($ntlmInfo.V1Count) Anmeldungen)" -ForegroundColor Red
    }

    # ZIP
    $zip = Compress-Report -FolderPath $reportDir

    # E-Mail
    if ($SendMail -and $MailTo -and $SmtpServer) {
        if (-not $MailFrom) { $MailFrom = "rc4audit@$($env:USERDNSDOMAIN)" }
        Send-Report -ZipPath $zip -To $MailTo -From $MailFrom -Smtp $SmtpServer
    }

    # Final summary with German interpretation
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  RC4 Environment Discovery abgeschlossen." -ForegroundColor Cyan
    Write-Host "  Domaene : $domainFQDN" -ForegroundColor White
    Write-Host "  Report  : $reportDir" -ForegroundColor White
    if ($zip) { Write-Host "  ZIP     : $zip" -ForegroundColor White }

    # --- German plaintext interpretation ---
    Write-Host ""
    Write-Host "  --- BEWERTUNG ---" -ForegroundColor Yellow

    # GPO
    if ($gpo.Value -eq 2147483647) {
        Write-Host "  [GPO] Fehler: Die Kerberos-GPO erlaubt alle Verschluesselungstypen" -ForegroundColor Red
        Write-Host "         einschliesslich DES. DES ist seit 2008 gebrochen." -ForegroundColor Red
        Write-Host "         Empfehlung: GPO sofort auf 2147483644 (DES entfernen) aendern." -ForegroundColor Red
    }
    elseif ($gpo.HasDES) {
        Write-Host "  [GPO] Fehler: DES noch erlaubt. Sofort entfernen." -ForegroundColor Red
    }
    elseif ($gpo.HasRC4) {
        Write-Host "  [GPO] Uebergang: RC4 noch erlaubt (Wert $($gpo.Value))." -ForegroundColor Yellow
        Write-Host "         Das ist akzeptabel solange die Account-Bereinigung laeuft." -ForegroundColor Yellow
        Write-Host "         Ziel: 2147483640 (AES-only) sobald alle Accounts bereinigt sind." -ForegroundColor Yellow
    }
    elseif ($gpo.Value) {
        Write-Host "  [GPO] OK: AES-only. Zielzustand erreicht." -ForegroundColor Green
    }
    else {
        Write-Host "  [GPO] Nicht konfiguriert — folgt OS-Default." -ForegroundColor DarkGray
        Write-Host "         Ab April 2026 (CVE-2026-20833) aendert sich der Default auf AES-only." -ForegroundColor DarkGray
    }

    # RC4 Systems
    if ((SafeCount $rc4Risk) -gt 0) {
        Write-Host ""
        Write-Host "  [SYSTEME] $((SafeCount $rc4Risk)) Systeme haben RC4 oder DES im Kerberos-Attribut:" -ForegroundColor Yellow
        foreach ($sys in $rc4Risk) {
            $color = if ($sys.EncCategory -eq 'RC4_ONLY') {'Red'} else {'Yellow'}
            Write-Host "    $($sys.Name.PadRight(25)) $($sys.EncCategory.PadRight(12)) $($sys.Role)" -ForegroundColor $color
        }
        Write-Host "         Diese Systeme koennen vom KDC RC4-Tickets erhalten." -ForegroundColor Yellow
        Write-Host "         Bei Server 2025 DCs oder nach dem April-2026-Update" -ForegroundColor Yellow
        Write-Host "         schlagen Authentifizierungen gelegentlich fehl." -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host "  [SYSTEME] Keine Systeme mit RC4/DES im Kerberos-Attribut gefunden." -ForegroundColor Green
    }

    # Delegation
    if ((SafeCount $delegRC4) -gt 0) {
        Write-Host ""
        Write-Host "  [DELEGATION] $((SafeCount $delegRC4)) Delegation-Accounts mit RC4/DES:" -ForegroundColor Red
        foreach ($d in $delegRC4) {
            Write-Host "    $($d.Name.PadRight(25)) $($d.EncCategory.PadRight(12)) $($d.DelegationType) -> $($d.DelegateTo.Substring(0, [Math]::Min(50, $d.DelegateTo.Length)))" -ForegroundColor Red
        }
        Write-Host "         Delegation-Accounts sind besonders kritisch weil die" -ForegroundColor Red
        Write-Host "         Encryption des delegierten Tickets von DIESEM Account" -ForegroundColor Red
        Write-Host "         abhaengt, nicht vom Benutzer." -ForegroundColor Red
    }

    # Events interpretation
    if ($events) {
        Write-Host ""
        $rc4Count = SafeCount $events.RC4Tickets
        $preAuthCount = SafeCount $events.PreAuthFails
        $lockoutCount = SafeCount $events.Lockouts
        $correlCount = SafeCount $events.Correlated

        if ($rc4Count -gt 0) {
            Write-Host "  [TICKETS] $rc4Count RC4-verschluesselte Service Tickets in den letzten $Hours Stunden." -ForegroundColor Red
            Write-Host "         Der KDC stellt aktiv RC4-Tickets aus. Diese werden von" -ForegroundColor Red
            Write-Host "         Server 2025 Systemen abgelehnt." -ForegroundColor Red
        }
        else {
            Write-Host "  [TICKETS] Keine RC4 Service Tickets in den letzten $Hours Stunden." -ForegroundColor Green
            Write-Host "         Der KDC waehlt aktuell AES. Das kann sich aendern wenn" -ForegroundColor DarkGray
            Write-Host "         ein 2025 DC oder Constrained Delegation ins Spiel kommt." -ForegroundColor DarkGray
        }

        if ($correlCount -gt 0) {
            Write-Host ""
            Write-Host "  [KORRELATION] $correlCount Kontosperrungen innerhalb 120 Sekunden" -ForegroundColor Red
            Write-Host "         nach einem Kerberos Pre-Auth Fehler (Fallback-Kette):" -ForegroundColor Red
            Write-Host "         Kerberos schlaegt fehl -> System versucht NTLM ->" -ForegroundColor Red
            Write-Host "         altes/falsches Kennwort -> Kontosperrung." -ForegroundColor Red
            Write-Host ""
            $correlAccounts = @($events.Correlated | Group-Object Account | Sort-Object Count -Descending)
            foreach ($ca in $correlAccounts | Select-Object -First 5) {
                Write-Host "    $($ca.Name.PadRight(30)) $($ca.Count)x gesperrt durch Fallback-Kette" -ForegroundColor Red
            }
        }
        elseif ($lockoutCount -gt 0) {
            Write-Host ""
            Write-Host "  [LOCKOUTS] $lockoutCount Kontosperrungen, aber keine Korrelation" -ForegroundColor Yellow
            Write-Host "         mit Kerberos-Fehlern. Ursache vermutlich nicht RC4-bedingt." -ForegroundColor Yellow
        }

        if ($preAuthCount -gt 50) {
            Write-Host ""
            Write-Host "  [PRE-AUTH] $preAuthCount Pre-Auth Fehler (Event 4771) in $Hours Stunden." -ForegroundColor Yellow
            Write-Host "         Erhoehte Anzahl. Haeufige Ursachen: gespeicherte alte" -ForegroundColor Yellow
            Write-Host "         Kennwoerter, Dienste mit falschem Passwort, Kerberos-Fallback." -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  --- NAECHSTE SCHRITTE ---" -ForegroundColor Cyan
    Write-Host "  1. Alle Systeme mit RC4_ONLY oder DES_PRESENT sofort auf AES-only setzen" -ForegroundColor White
    Write-Host "  2. Systeme mit RC4_AES auf AES-only umstellen (Wert 24)" -ForegroundColor White
    Write-Host "  3. Delegation-Accounts pruefen und Keytabs mit AES neu erstellen" -ForegroundColor White
    Write-Host "  4. KRBTGT-Kennwort pruefen: Get-ADUser krbtgt -Prop PasswordLastSet" -ForegroundColor White
    Write-Host "  5. Prove-RC4Usage.ps1 ausfuehren um aktive RC4-Tickets zu finden" -ForegroundColor White
    Write-Host "  6. GPO auf 2147483640 (AES-only) aendern wenn alle Accounts bereinigt" -ForegroundColor White
    Write-Host "  7. Deadline: April 2026 (CVE-2026-20833) — neuer Default AES-only" -ForegroundColor White
    Write-Host ""
    Write-Host "  Referenzen:" -ForegroundColor DarkGray
    Write-Host "  - https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos" -ForegroundColor DarkGray
    Write-Host "  - https://www.msxfaq.de/windows/kerberos/kerberos_rc4_abschaltung.htm" -ForegroundColor DarkGray
    Write-Host "  - https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/" -ForegroundColor DarkGray
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ""

    } # end elseif (-not $script:_IsDotSourced)

    #endregion
    # Ergebnisordner fuer -Mode Full merken (auch im Reassess-Zweig korrekt)
    $script:LastRC4ReportDir = $reportDir
}
#endregion

#region ============ MODUS: REPORT (Plain — XLSX + HTML) ============
function Invoke-ReportPlain {
    Set-StrictMode -Version 2   # wie im Original
    # Kapselung: eigene SafeCount/Normalize-TypLabel/Import-OptionalCsv bleiben lokal
    $ReportPath = $ReportSource
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'

    #region ============ HELPERS ============

    function SafeCount { param($C) if ($null -eq $C) {0} elseif ($C -is [array]) {$C.Length} else {1} }

    function Normalize-TypLabel {
        param([string]$Typ)
        switch ($Typ) {
            'AKTIV'              { 'Fehler' }
            'KRITISCH'           { 'Fehler' }
            'SCHLAFEND'          { 'Warnung' }
            'UEBERGANG'          { 'Warnung' }
            'PRUEFEN'            { 'Warnung' }
            'PASSIV'             { 'Information' }
            'IMPLIZIT MITIGIERT' { 'Information' }
            'OHNE FOLGEN'        { 'Information' }
            'OHNE_FOLGEN'        { 'Information' }
            'GETRENNT'           { 'Information' }
            'HINWEIS'            { 'Information' }
            'OK'                 { 'Information' }
            default              { $Typ }
        }
    }

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
        Nr=1; Typ=if($rc4TicketCount -gt 0){'Fehler'}else{'Information'}
        Titel='RC4 in Computer/Service Accounts'
        Befund="$rc4RiskCount Accounts haben RC4 oder DES im Attribut msDS-SupportedEncryptionTypes. $rc4TicketCount RC4-verschluesselte Service Tickets in den letzten 24 Stunden."
        Betroffene=$f1Impact
        Auswirkung=if($rc4TicketCount -gt 0){"Der KDC stellt aktiv RC4-Tickets aus. Server 2025 Systeme lehnen diese ab. Authentifizierung schlaegt bei ca. $rc4TicketCount Verbindungen pro Tag fehl."}else{"Aktuell kein Ausfall — der KDC waehlt AES. Das Risiko wird aktiv bei Server 2025 DC Promotion, Exchange SE Go-Live unter Last, oder dem April-2026-Update (CVE-2026-20833)."}
        Mitigation="Alle betroffenen Accounts auf Wert 24 (AES-only) setzen:`nSet-ADComputer '<Name>' -KerberosEncryptionType AES128,AES256`nDanach: Passwort rotieren damit AES-Keys generiert werden."
        Seiteneffekte=if($rc4TicketCount -eq 0){"Risikofrei — der KDC stellt bereits AES-Tickets fuer diese Accounts aus. Die Aenderung formalisiert den Ist-Zustand."}else{"Systeme die nur RC4 koennen (z.B. SAP < 7.53, Igel alte FW) verlieren Zugang. Vorher mit Prove-RC4Usage.ps1 pruefen welche SPNs RC4-Tickets erhalten."}
    }

    # --- Finding 2: GPO ---
    $gpoStatus = if (-not $gpo -or -not $gpo.Value) {'Warnung'} elseif ($gpo.HasDES) {'Warnung'} elseif ($gpo.HasRC4) {'Warnung'} else {'Information'}
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
            Nr=3; Typ='Warnung'
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
            Nr=4; Typ='Warnung'
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
            Nr=5; Typ=if($rc4TicketCount -gt 0){'Fehler'}else{'Warnung'}
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
        Nr=6; Typ=if($rc4TicketCount -eq 0){'Information'}else{'Warnung'}
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
            Nr=7; Typ='Information'
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
            Nr=8; Typ='Warnung'
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
                Nr=9; Typ=if((SafeCount $smbMismatch) -gt 0){'Warnung'}elseif((SafeCount $allTrue) -eq (SafeCount $smbCsv)){'Information'}else{'Information'}
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
            Nr=10; Typ='Fehler'
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
            Nr=11; Typ='Fehler'
            Titel='NTLMv1 Anmeldungen — kryptographisch gebrochen'
            Befund="$(($ntlmV1 | Measure-Object -Property Count -Sum).Sum) NTLMv1-Anmeldungen erkannt. NTLMv1 ist durch Mandiant Rainbow Tables sofort kompromittierbar."
            Betroffene=$v1Top
            Auswirkung="Jede NTLMv1-Anmeldung kann durch einen Angreifer im Netzwerk abgefangen und das Passwort sofort wiederhergestellt werden. NTLMv1 ist ein groesseres Sicherheitsrisiko als RC4 in Kerberos."
            Mitigation="GPO: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM and NTLM. Betroffene Systeme (alte Firmware, alte Applikationen) identifizieren und auf NTLMv2 oder Kerberos umstellen."
            Seiteneffekte="Systeme die nur NTLMv1 koennen verlieren Zugang. Betrifft typischerweise sehr alte Appliances, Drucker oder Legacy-Software."
        }
    }

    # --- Priority sort: Fehler first, then Warnung, then Information ---
    # Normalize any old labels (from older Discover CSVs or future changes)
    foreach ($f in $findings) { $f.Typ = Normalize-TypLabel $f.Typ }
    $typPrio = @{ 'Fehler'=1; 'Warnung'=2; 'Information'=3 }
    $findings = @($findings | Sort-Object { if ($typPrio[$_.Typ]) { $typPrio[$_.Typ] } else { 99 } }, Nr)

    Write-Host "`n  $((SafeCount $findings)) Findings generiert (Fehler zuerst)" -ForegroundColor Cyan

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
.fehler { background: #FCEBEB; color: #791F1F; }
.warnung { background: #FFF8E1; color: #633806; }
.information { background: #E1F5EE; color: #085041; }
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
        'Fehler'='fehler'; 'Warnung'='warnung'; 'Information'='information'
    }

    $fehlerCount = @($findings | Where-Object { $_.Typ -eq 'Fehler' }).Count
    $warnCount = @($findings | Where-Object { $_.Typ -eq 'Warnung' }).Count
    $infoCount = @($findings | Where-Object { $_.Typ -eq 'Information' }).Count

    $htmlBody = @"
<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>RC4 Risikobewertung — $DomainLabel</title>
<style>$css</style></head><body>
<h1>Risikobewertung Kerberos RC4 — $DomainLabel</h1>
<p class="meta">Erstellt: $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Quelle: $ReportPath</p>

<div class="summary-grid">
<div class="summary-card"><div class="label">Fehler</div><div class="value" style="color:$(if($fehlerCount -gt 0){'#791F1F'}else{'#085041'})">$fehlerCount</div></div>
<div class="summary-card"><div class="label">Warnungen</div><div class="value" style="color:$(if($warnCount -gt 0){'#633806'}else{'#085041'})">$warnCount</div></div>
<div class="summary-card"><div class="label">Information</div><div class="value" style="color:#085041">$infoCount</div></div>
<div class="summary-card"><div class="label">Systeme mit RC4/DES</div><div class="value">$rc4RiskCount</div></div>
<div class="summary-card"><div class="label">RC4 Tickets (24h)</div><div class="value" style="color:$(if($rc4TicketCount -gt 0){'#791F1F'}else{'#085041'})">$rc4TicketCount</div></div>
<div class="summary-card"><div class="label">GPO</div><div class="value" style="font-size:14px">$gpoVal</div></div>
</div>

<h2>Findings (Fehler zuerst)</h2>
"@

    # Priority header
    $fehlerFindings = @($findings | Where-Object { $_.Typ -eq 'Fehler' })
    if ($fehlerFindings.Count -gt 0) {
        $htmlBody += '<div style="background:#FCEBEB;border-left:4px solid #C8102E;padding:12px 16px;margin:12px 0;border-radius:0 6px 6px 0;"><strong style="color:#791F1F;">Sofort handeln:</strong> '
        $htmlBody += ($fehlerFindings | ForEach-Object { "#$($_.Nr) $($_.Titel)" }) -join ' | '
        $htmlBody += '</div>'
    }
    $warnFindings = @($findings | Where-Object { $_.Typ -eq 'Warnung' })
    if ($warnFindings.Count -gt 0) {
        $htmlBody += '<div style="background:#FFF8E1;border-left:4px solid #EF9F27;padding:12px 16px;margin:12px 0;border-radius:0 6px 6px 0;"><strong style="color:#633806;">Vor April 2026:</strong> '
        $htmlBody += ($warnFindings | ForEach-Object { "#$($_.Nr) $($_.Titel)" }) -join ' | '
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
        $overview += [PSCustomObject]@{ Bereich='Fehler'; Wert=$fehlerCount; Status=if($fehlerCount -gt 0){'Fehler'}else{'Information'} }
        $overview += [PSCustomObject]@{ Bereich='Warnungen'; Wert=$warnCount; Status=if($warnCount -gt 0){'Warnung'}else{'Information'} }
        $overview += [PSCustomObject]@{ Bereich='Information'; Wert=$infoCount; Status='Information' }
        $overview += [PSCustomObject]@{ Bereich='Systeme mit RC4/DES'; Wert=$rc4RiskCount; Status=if($rc4RiskCount -gt 0){'Warnung'}else{'Information'} }
        $overview += [PSCustomObject]@{ Bereich='RC4 Tickets (24h)'; Wert=$rc4TicketCount; Status=if($rc4TicketCount -gt 0){'Fehler'}else{'Information'} }
        $overview += [PSCustomObject]@{ Bereich='GPO Wert'; Wert=$gpoVal; Status=$gpoStatus }
        $overview += [PSCustomObject]@{ Bereich='Urgent Fixes'; Wert=(SafeCount $urgentFix); Status=if((SafeCount $urgentFix) -gt 0){'Warnung'}else{'Information'} }

        $ctStatus = @(
            (New-ConditionalText 'Fehler' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'Warnung'  -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            (New-ConditionalText 'Information'       -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
        )

        $overview | Export-Excel -Path $xlFile -WorksheetName 'Uebersicht' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $ctStatus

        # --- Tab 2: Findings ---
        $ctFindings = @(
            (New-ConditionalText 'Fehler'      -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'Warnung'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            (New-ConditionalText 'Information' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
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
}
#endregion

#region ============ MODUS: REPORT (DG — Corporate Design HTML) ============
function Invoke-ReportDG {
    Set-StrictMode -Version 2   # wie im Original
    # Kapselung wie Plain; Klassen DGColor/DGHtml/DGDocument sind global (Parse-Zeit)
    $ReportPath = $ReportSource
    # ═══════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════

    function SafeCount { param($C) if ($null -eq $C) {0} elseif ($C -is [array]) {$C.Length} else {1} }

    function Import-OptionalCsv {
        param([string]$Path)
        if (-not (Test-Path $Path)) { return @() }
        try { @(Import-Csv $Path -Delimiter ';' -Encoding UTF8) } catch { @() }
    }

    function Normalize-TypLabel {
        param([string]$Typ)
        switch ($Typ) {
            'AKTIV'              { 'Fehler' }
            'KRITISCH'           { 'Fehler' }
            'SCHLAFEND'          { 'Warnung' }
            'UEBERGANG'          { 'Warnung' }
            'PRUEFEN'            { 'Warnung' }
            'PASSIV'             { 'Information' }
            'IMPLIZIT MITIGIERT' { 'Information' }
            'OHNE FOLGEN'        { 'Information' }
            'OHNE_FOLGEN'        { 'Information' }
            'GETRENNT'           { 'Information' }
            'HINWEIS'            { 'Information' }
            'OK'                 { 'Information' }
            default              { $Typ }
        }
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

    # ═══════════════════════════════════════════════════════════════
    # DATA LOADING
    # ═══════════════════════════════════════════════════════════════

    Write-Host "`n=== RC4 Report (Corporate Design) ===" -ForegroundColor Cyan
    Write-Host "  Quelle: $ReportPath"

    if (-not (Test-Path $ReportPath)) {
        Write-Host "  FEHLER: Pfad nicht gefunden." -ForegroundColor Red; return
    }

    if (-not $DomainLabel) {
        $folder = Split-Path $ReportPath -Leaf
        if ($folder -match 'RC4_([^_]+)_') { $DomainLabel = $Matches[1] } else { $DomainLabel = 'UNKNOWN' }
    }

    # Load all CSVs
    $citrix    = Import-OptionalCsv (Join-Path $ReportPath 'Citrix.csv')
    $igel      = Import-OptionalCsv (Join-Path $ReportPath 'Igel.csv')
    $nonwin    = Import-OptionalCsv (Join-Path $ReportPath 'NonWindows.csv')
    $deleg     = Import-OptionalCsv (Join-Path $ReportPath 'Delegation.csv')
    $gpoCsv    = Import-OptionalCsv (Join-Path $ReportPath 'GPO_Policy.csv')
    $preAuth   = Import-OptionalCsv (Join-Path $ReportPath 'PreAuthFails.csv')
    $lockouts  = Import-OptionalCsv (Join-Path $ReportPath 'Lockouts.csv')
    $correl    = Import-OptionalCsv (Join-Path $ReportPath 'Correlated.csv')

    $rc4Tickets = Import-OptionalCsv (Join-Path $ReportPath 'RC4Tickets.csv')
    if ((SafeCount $rc4Tickets) -eq 0) { $rc4Tickets = Import-OptionalCsv (Join-Path $ReportPath 'RC4_Tickets.csv') }

    # SMB from Check-Server2025Defaults
    $smbFiles = @(Get-ChildItem $ReportPath -Filter 'SMB_Kerberos_report_*.csv' -EA SilentlyContinue | Where-Object { $_.Name -notmatch 'Kerberos|recommendation|urgent' })
    $smbFiles += @(Get-ChildItem $ReportPath -Filter 'Audit_*.csv' -EA SilentlyContinue | Where-Object { $_.Name -notmatch 'Kerberos|recommendation|urgent' })
    $smbCsv = if ($smbFiles.Count -gt 0) { Import-OptionalCsv $smbFiles[0].FullName } else { @() }

    $urgFiles = @(Get-ChildItem $ReportPath -Filter '*_urgent_fix.csv' -EA SilentlyContinue)
    $urgentFix = if ($urgFiles.Count -gt 0) { Import-OptionalCsv $urgFiles[0].FullName } else { @() }

    $kerbFiles = @(Get-ChildItem $ReportPath -Filter '*_KerberosAudit.csv' -EA SilentlyContinue)
    $kerbAudit = if ($kerbFiles.Count -gt 0) { Import-OptionalCsv $kerbFiles[0].FullName } else { @() }

    $preAuthDetail = @()
    $padFiles = @(Get-ChildItem $ReportPath -Filter 'PreAuth_Detail_*.csv' -EA SilentlyContinue)
    if ($padFiles.Count -gt 0) { $preAuthDetail = Import-OptionalCsv $padFiles[0].FullName }

    $kdcsvcEvents = Import-OptionalCsv (Join-Path $ReportPath 'KDCSVC_Audit.csv')
    $ntlmV1 = Import-OptionalCsv (Join-Path $ReportPath 'NTLMv1_Usage.csv')

    # GPO
    $gpo = $null
    if ((SafeCount $gpoCsv) -gt 0) {
        $row = $gpoCsv | Select-Object -First 1
        $gpoVal = if ($row.Value -and $row.Value -ne '') { try { [int]$row.Value } catch { $null } } else { $null }
        $gpo = [PSCustomObject]@{
            Value=$gpoVal; HasDES=$($row.HasDES -eq 'True'); HasRC4=$($row.HasRC4 -eq 'True')
            HasAES128=$($row.HasAES128 -eq 'True'); HasAES256=$($row.HasAES256 -eq 'True')
        }
    }

    # Computed values
    $allDiscovery = @() + $citrix + $igel + $nonwin
    $rc4Risk = @($allDiscovery | Where-Object { $cat = if ($_.EncCategory) {$_.EncCategory} else {'UNKNOWN'}; $cat -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
    $delegRC4 = @($deleg | Where-Object { $cat = if ($_.EncCategory) {$_.EncCategory} else {'UNKNOWN'}; $cat -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
    $notSet = @($allDiscovery | Where-Object { $_.EncCategory -eq 'NOT_SET' })
    $rc4TicketCount = SafeCount $rc4Tickets
    $gpoVal = if ($gpo) { $gpo.Value } else { 'Nicht gesetzt' }
    $trustsUrgent = @($urgentFix | Where-Object { $_.Roles -eq 'Trust' -or $_.Issue -match 'Trust' })
    $dcsDES = @($urgentFix | Where-Object { $_.Issue -match 'DES enabled' })

    Write-Host "  Domain     : $DomainLabel" -ForegroundColor White
    Write-Host "  Systeme    : $(SafeCount $allDiscovery) ($(SafeCount $rc4Risk) mit RC4/DES)" -ForegroundColor DarkGray
    Write-Host "  RC4 Tickets: $rc4TicketCount" -ForegroundColor DarkGray
    Write-Host "  Urgent Fix : $(SafeCount $urgentFix)" -ForegroundColor DarkGray

    # ═══════════════════════════════════════════════════════════════
    # FINDINGS ENGINE (same as New-RC4Report.ps1)
    # ═══════════════════════════════════════════════════════════════

    $findings = @()

    # F1: RC4 in Accounts
    $f1Typ = if ($rc4TicketCount -gt 0) {'Fehler'} else {'Information'}
    $f1Impact = @($rc4Risk | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Role), $($_.EncCategory))" }) -join "`n"
    if ((SafeCount $rc4Risk) -gt 10) { $f1Impact += "`n... und $((SafeCount $rc4Risk) - 10) weitere" }
    $findings += [PSCustomObject]@{
        Nr=1; Typ=$f1Typ; Titel='RC4 in Computer/Service Accounts'
        Befund="$(SafeCount $rc4Risk) Accounts mit RC4 oder DES. $rc4TicketCount RC4-Tickets in 24h."
        Betroffene=$f1Impact
        Auswirkung=if($rc4TicketCount -gt 0){"Der KDC stellt aktiv RC4-Tickets aus. Diese werden von Server 2025 Systemen abgelehnt."}else{"Aktuell kein Ausfall — der KDC waehlt AES. Auf Wert 24 setzen formalisiert den Ist-Zustand und ist risikofrei."}
        Mitigation="Betroffene Accounts auf Wert 24 (AES-only) setzen:`nSet-ADComputer '&lt;Name&gt;' -KerberosEncryptionType AES128,AES256`nDanach Passwort rotieren damit AES-Keys generiert werden."
        Seiteneffekte=if($rc4TicketCount -eq 0){"Risikofrei — der KDC stellt bereits AES-Tickets fuer diese Accounts aus."}else{"Systeme die nur RC4 koennen verlieren Zugang. Vorher mit Prove-RC4Usage.ps1 pruefen."}
    }

    # F2: GPO
    $f2Typ = if ($gpo -and $gpo.HasDES) {'Warnung'} elseif (-not $gpo -or -not $gpo.Value) {'Warnung'} else {'Information'}
    $findings += [PSCustomObject]@{
        Nr=2; Typ=$f2Typ; Titel='Kerberos GPO Encryption Policy'
        Befund="GPO-Wert: $gpoVal. $(if($gpo -and $gpo.HasDES){'DES und RC4 erlaubt.'}elseif(-not $gpo -or -not $gpo.Value){'Nicht konfiguriert — folgt OS-Default.'}else{'Nur AES erlaubt.'})"
        Betroffene="Alle Kerberos-Authentifizierungen in $DomainLabel"
        Auswirkung=if($gpo -and $gpo.HasDES){"DES ist kryptographisch gebrochen. Die GPO haelt die Tuer fuer Kerberoasting offen."}else{"Ab April 2026 wird der Default auf AES-only geaendert."}
        Mitigation=if($gpo -and $gpo.HasDES){"GPO sofort auf 2147483644 aendern (DES entfernen). Ziel: 2147483640 (AES-only)."}else{"GPO explizit auf 2147483644 setzen. Vor April 2026 auf 2147483640."}
        Seiteneffekte=if($gpo -and $gpo.HasDES -and $rc4TicketCount -eq 0){"Risikofrei — 0 DES/RC4-Traffic."}else{"Keine bei aktuellem Wert."}
    }

    # F3: Trusts
    if ((SafeCount $trustsUrgent) -gt 0) {
        $trustNames = ($trustsUrgent | ForEach-Object { $_.ComputerName }) -join ', '
        $findings += [PSCustomObject]@{
            Nr=3; Typ='Warnung'; Titel='Trust-Objekte ohne AES'
            Befund="$(SafeCount $trustsUrgent) Trust(s) ohne AES: $trustNames"
            Betroffene=$trustNames
            Auswirkung="Cross-Domain-Authentifizierung verwendet RC4. Nach April 2026 schlaegt Cross-Domain-Auth fehl."
            Mitigation=($trustsUrgent | ForEach-Object { $_.Fix }) -join "`n"
            Seiteneffekte="ksetup fuegt AES hinzu und belaesst RC4 als Fallback. Kein Risiko."
        }
    }

    # F4: DCs mit DES
    if ((SafeCount $dcsDES) -gt 0) {
        $dcNames = ($dcsDES | ForEach-Object { $_.ComputerName }) -join ', '
        $findings += [PSCustomObject]@{
            Nr=4; Typ='Warnung'; Titel='Domain Controller mit DES'
            Befund="$(SafeCount $dcsDES) DCs mit Wert 31 (DES+RC4+AES): $dcNames"
            Betroffene=$dcNames
            Auswirkung="Bei Kerberoasting-Angriffen sind DES-Tickets leichter zu knacken."
            Mitigation="Set-ADComputer '&lt;DC&gt;' -KerberosEncryptionType AES128,AES256`nWICHTIG: GPO pruefen — sonst setzt gpupdate den Wert zurueck."
            Seiteneffekte="Risikofrei wenn die GPO ebenfalls angepasst wird."
        }
    }

    # F5: Delegation
    if ((SafeCount $delegRC4) -gt 0) {
        $delegNames = ($delegRC4 | ForEach-Object { "$($_.Name) ($($_.DelegationType))" }) -join "`n"
        $findings += [PSCustomObject]@{
            Nr=5; Typ=if($rc4TicketCount -gt 0){'Fehler'}else{'Warnung'}; Titel='Delegation-Accounts mit RC4/DES'
            Befund="$(SafeCount $delegRC4) Constrained Delegation Accounts mit RC4 oder DES."
            Betroffene=$delegNames
            Auswirkung="Unter hoher Last kann der KDC RC4 fuer delegierte Tickets waehlen."
            Mitigation="Accounts auf Wert 24 setzen + Keytabs mit AES neu erstellen."
            Seiteneffekte=if($rc4TicketCount -eq 0){"Risikofrei bei 0 RC4-Traffic."}else{"Keytab muss VOR der Account-Aenderung neu erstellt werden."}
        }
    }

    # F6: SAP
    $findings += [PSCustomObject]@{
        Nr=6; Typ=if($rc4TicketCount -eq 0){'Information'}else{'Warnung'}; Titel='SAP Kerberos-Kompatibilitaet'
        Befund=if($rc4TicketCount -eq 0){"0 RC4-Tickets — SAP erhaelt und akzeptiert AES-Tickets."}else{"$rc4TicketCount RC4-Tickets — pruefen ob SAP-SPNs betroffen sind."}
        Betroffene='SAP Application Server'
        Auswirkung=if($rc4TicketCount -eq 0){"Ohne Folgen. SAP funktioniert mit AES."}else{"SAP Kernel Update auf >= 7.53 erforderlich falls betroffen."}
        Mitigation=if($rc4TicketCount -eq 0){"Keine Aktion noetig."}else{"RC4-Tickets nach SAP-SPNs filtern."}
        Seiteneffekte='Keine.'
    }

    # F7: PreAuth
    $preAuthCount = SafeCount $preAuth
    if ($preAuthCount -gt 50) {
        $topAccounts = ''
        if ((SafeCount $preAuthDetail) -gt 0) {
            $topAccounts = @($preAuthDetail | Where-Object { $_.Status -eq '0x18' } | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count)x)" }) -join ', '
        }
        $findings += [PSCustomObject]@{
            Nr=7; Typ='Information'; Titel='Pre-Authentication Fehler (Credential-Hygiene)'
            Befund="$preAuthCount Pre-Auth Fehler, 0 RC4-Tickets, $(SafeCount $correl) korrelierte Lockouts."
            Betroffene=if($topAccounts){$topAccounts}else{"Details in PreAuthFails.csv"}
            Auswirkung="Kein RC4-Problem. Ursache: falsche Passwoerter. Wird relevant nach April 2026 wenn die Fallback-Kette seltener greift."
            Mitigation="Betroffene Accounts identifizieren. Haeufigste Ursachen: Outlook-Profile, ActiveSync, Scheduled Tasks."
            Seiteneffekte='Keine.'
        }
    }

    # F8: NOT SET
    if ((SafeCount $notSet) -gt 0) {
        $findings += [PSCustomObject]@{
            Nr=8; Typ='Warnung'; Titel='Accounts ohne expliziten Verschluesselungstyp (Wert 0)'
            Befund="$(SafeCount $notSet) Accounts mit Wert 0 (NOT SET)."
            Betroffene=(@($notSet | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Role))" }) -join ', ') + $(if ((SafeCount $notSet) -gt 10) { " ... +$((SafeCount $notSet) - 10) weitere" })
            Auswirkung="Ab April 2026 wird der Default auf AES-only geaendert. Diese Accounts schlagen fehl wenn sie RC4 benoetigen."
            Mitigation="Explizit auf Wert 24 (AES-only) setzen. Deadline: vor dem April-2026-Patchday."
            Seiteneffekte='Beim Setzen auf 24: Systeme die nur RC4 koennen verlieren Zugang.'
        }
    }

    # F9: KDCSVC
    if ((SafeCount $kdcsvcEvents) -gt 0) {
        $findings += [PSCustomObject]@{
            Nr=9; Typ='Fehler'; Titel='KDCSVC Audit Events (Januar 2026 CU)'
            Befund="$(SafeCount $kdcsvcEvents) KDCSVC Events im System Log."
            Betroffene=(@($kdcsvcEvents | Group-Object EventID | Sort-Object Name | ForEach-Object { "Event $($_.Name): $($_.Count)x" }) -join ', ')
            Auswirkung="Diese Accounts werden ab April 2026 bei der Authentifizierung abgelehnt."
            Mitigation="Betroffene Accounts auf AES-only (Wert 24) setzen und Passwort rotieren."
            Seiteneffekte='Risikofrei wenn die Accounts aktuell AES-Tickets erhalten.'
        }
    }

    # F10: NTLMv1
    if ((SafeCount $ntlmV1) -gt 0) {
        $v1Top = ($ntlmV1 | Sort-Object { [int]$_.Count } -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Account) ($($_.Count)x)" }) -join '; '
        $findings += [PSCustomObject]@{
            Nr=10; Typ='Fehler'; Titel='NTLMv1 Anmeldungen — kryptographisch gebrochen'
            Befund="$(($ntlmV1 | Measure-Object -Property Count -Sum).Sum) NTLMv1-Anmeldungen."
            Betroffene=$v1Top
            Auswirkung="NTLMv1 kann durch Mandiant Rainbow Tables sofort kompromittiert werden. Groesseres Risiko als RC4."
            Mitigation="GPO: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM and NTLM."
            Seiteneffekte='Sehr alte Appliances oder Drucker die nur NTLMv1 koennen verlieren Zugang.'
        }
    }

    # Normalize and sort
    foreach ($f in $findings) { $f.Typ = Normalize-TypLabel $f.Typ }
    $typPrio = @{ 'Fehler'=1; 'Warnung'=2; 'Information'=3 }
    $findings = @($findings | Sort-Object { if ($typPrio[$_.Typ]) { $typPrio[$_.Typ] } else { 99 } }, Nr)

    $fehlerCount = @($findings | Where-Object { $_.Typ -eq 'Fehler' }).Count
    $warnCount   = @($findings | Where-Object { $_.Typ -eq 'Warnung' }).Count
    $infoCount   = @($findings | Where-Object { $_.Typ -eq 'Information' }).Count

    Write-Host "  Findings   : $(SafeCount $findings) (Fehler: $fehlerCount, Warnung: $warnCount, Information: $infoCount)" -ForegroundColor Cyan

    # ═══════════════════════════════════════════════════════════════
    # BUILD DOCUMENT
    # ═══════════════════════════════════════════════════════════════

    $doc = [DGDocument]::new(
        "RC4 Risikobewertung — $DomainLabel",
        'Risikobewertung',
        'Kerberos RC4 / Server 2025',
        "RC4 Risikobewertung"
    )
    $h = $doc.Html

    # ══════════ TITLE PAGE ══════════
    $h.Title("RC4 Risikobewertung")
    $h.SubtitleRed("$DomainLabel — Kerberos Encryption Audit")
    $h.RedDivider()
    $h.MetaTable(@(
        @("Dokumenttyp:", "Risikobewertung — Kerberos RC4 Abschaltung (CVE-2026-20833)"),
        @("Domäne:", $DomainLabel),
        @("Stichtag:", (Get-Date -Format 'yyyy-MM-dd HH:mm')),
        @("Erstellt von:", $Author),

        @("Datenquelle:", (Split-Path $ReportPath -Leaf))
    ))
    $h.Spacer()
    $h.Body("Dieser Report bewertet die Kerberos-Verschlüsselungskonfiguration der Domäne $DomainLabel im Hinblick auf die Microsoft RC4-Abschaltung (CVE-2026-20833). Er identifiziert Systeme, Accounts und Konfigurationen die bei der Umstellung fehlschlagen können und dokumentiert konkrete Maßnahmen mit Seiteneffekt-Bewertung.")

    # ══════════ SUMMARY ══════════
    $h.PageBreak()
    $h.H1("Zusammenfassung")

    $h.AppendLine("<div class='dg-summary-grid'>")
    $h.SummaryCard("Fehler", $fehlerCount, $(if ($fehlerCount -gt 0) {[DGColor]::Red} else {[DGColor]::Green}))
    $h.SummaryCard("Warnungen", $warnCount, $(if ($warnCount -gt 0) {[DGColor]::Amber} else {[DGColor]::Green}))
    $h.SummaryCard("Information", $infoCount, [DGColor]::Green)
    $h.SummaryCard("RC4-Systeme", (SafeCount $rc4Risk), $(if ((SafeCount $rc4Risk) -gt 0) {[DGColor]::Amber} else {[DGColor]::Green}))
    $h.SummaryCard("RC4-Tickets", $rc4TicketCount, $(if ($rc4TicketCount -gt 0) {[DGColor]::Red} else {[DGColor]::Green}))
    $h.SummaryCard("GPO", $gpoVal, $(if ($gpo -and $gpo.HasDES) {[DGColor]::Red} else {[DGColor]::Grey}))
    $h.AppendLine("</div>")

    $h.H2("CVE-2026-20833 — Zeitplan")
    $h.DataTable(@("Phase","Zeitraum","Auswirkung","Ruecknahme"), @(
        @("1. Audit","Januar 2026 (aktiv)","KDCSVC Events 201-209, Registry-Steuerung","Ja"),
        @("2. Enforcement","April 2026","Default wird AES-only fuer NOT SET Accounts","Ja (Rollback)"),
        @("3. Final","Juli 2026","Audit-Modus entfernt, Enforcement endgueltig","Nein")
    ))
    $h.Note("Accounts mit explizitem msDS-SupportedEncryptionTypes (z.B. Wert 28 oder 24) sind vom Enforcement <strong>nicht betroffen</strong>. Nur Accounts mit Wert 0 (NOT SET) aendern ihr Verhalten.")

    # ══════════ FINDINGS ══════════
    $h.PageBreak()
    $h.H1("Findings")

    # Priority banners
    $fehlerFindings = @($findings | Where-Object { $_.Typ -eq 'Fehler' })
    if ($fehlerFindings.Count -gt 0) {
        $list = ($fehlerFindings | ForEach-Object { "#$($_.Nr) $($_.Titel)" }) -join ' &nbsp;|&nbsp; '
        $h.AppendLine("<div style='background:#FCEBEB;border-left:4px solid $([DGColor]::Red);padding:8px 12px;margin:4mm 0;border-radius:0 4px 4px 0;font-size:9.5pt;'><strong style='color:$([DGColor]::Red);'>Sofort handeln:</strong> $list</div>")
    }
    $warnFindings = @($findings | Where-Object { $_.Typ -eq 'Warnung' })
    if ($warnFindings.Count -gt 0) {
        $list = ($warnFindings | ForEach-Object { "#$($_.Nr) $($_.Titel)" }) -join ' &nbsp;|&nbsp; '
        $h.AppendLine("<div style='background:#FFF8E1;border-left:4px solid $([DGColor]::Amber);padding:8px 12px;margin:4mm 0;border-radius:0 4px 4px 0;font-size:9.5pt;'><strong style='color:$([DGColor]::Amber);'>Vor April 2026:</strong> $list</div>")
    }

    foreach ($f in $findings) {
        $h.FindingCard($f.Nr, $f.Typ, $f.Titel, @{
            Befund       = $f.Befund
            Betroffene   = $f.Betroffene
            Auswirkung   = $f.Auswirkung
            Mitigation   = $f.Mitigation
            Seiteneffekte = $f.Seiteneffekte
        })
    }

    # ══════════ URGENT FIXES ══════════
    if ((SafeCount $urgentFix) -gt 0) {
        $h.PageBreak()
        $h.H1("Urgent Fixes")
        $h.Body("Diese Eintraege erfordern zeitnahes Handeln. Der Fix-Befehl kann direkt ausgefuehrt werden.")
        $rows = @($urgentFix | ForEach-Object {
            $cn = $_.ComputerName
            $role = $_.Roles
            $issue = $_.Issue
            $fix = $_.Fix -replace "'", "'" -replace '<', '&lt;'
            @($cn, $role, $issue, "<code style='font-size:8pt;'>$fix</code>")
        })
        $h.DataTable(@("System","Rolle","Problem","Fix"), $rows)
    }

    # ══════════ AFFECTED SYSTEMS ══════════
    if ((SafeCount $rc4Risk) -gt 0) {
        $h.PageBreak()
        $h.H1("Betroffene Systeme")

        if ((SafeCount $citrix) -gt 0) {
            $rc4Citrix = @($citrix | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
            if ($rc4Citrix.Count -gt 0) {
                $h.H2("Citrix ($($rc4Citrix.Count) mit RC4/DES)")
                $rows = @($rc4Citrix | Select-Object -First 30 | ForEach-Object {
                    $cat = $_.EncCategory
                    $color = switch ($cat) { 'RC4_ONLY' {[DGColor]::Red}; 'DES_PRESENT' {[DGColor]::Red}; 'RC4_AES' {[DGColor]::Amber}; default {[DGColor]::Grey} }
                    @($_.Name, $_.Role, "<span style='color:${color};font-weight:bold;'>$cat</span>", $(if ($_.Bewertung) {$_.Bewertung} else {''}))
                })
                $h.DataTable(@("Name","Rolle","EncType","Bewertung"), $rows)
            }
        }

        if ((SafeCount $delegRC4) -gt 0) {
            $h.H2("Delegation ($($delegRC4.Count) mit RC4/DES)")
            $rows = @($delegRC4 | ForEach-Object {
                @($_.Name, $_.DelegationType, $_.EncCategory, $(if ($_.DelegateTo) {$_.DelegateTo.Substring(0, [Math]::Min(60, $_.DelegateTo.Length))} else {''}))
            })
            $h.DataTable(@("Account","Delegation","EncType","DelegateTo"), $rows)
        }

        if ((SafeCount $nonwin) -gt 0) {
            $rc4Nonwin = @($nonwin | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
            if ($rc4Nonwin.Count -gt 0) {
                $h.H2("Non-Windows ($($rc4Nonwin.Count) mit RC4/DES)")
                $rows = @($rc4Nonwin | ForEach-Object { @($_.Name, $_.Role, $_.EncCategory, $(if ($_.Bewertung) {$_.Bewertung} else {''})) })
                $h.DataTable(@("Name","Rolle","EncType","Bewertung"), $rows)
            }
        }
    }

    # ══════════ REFERENCES ══════════
    $h.PageBreak()
    $h.H1("Referenzen")
    $h.Bullet("<a href='https://support.microsoft.com/de-de/topic/verwalten-der-kerberos-kdc-verwendung-von-rc4-1ebcda33-720a-4da8-93c1-b0496e1910dc'>Microsoft Support: CVE-2026-20833 — Kerberos KDC RC4</a>")
    $h.Bullet("<a href='https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos'>Microsoft Learn: Detect and Remediate RC4</a>")
    $h.Bullet("<a href='https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/'>Microsoft Blog: Beyond RC4 (Dezember 2025)</a>")
    $h.Bullet("<a href='https://www.msxfaq.de/windows/kerberos/kerberos_rc4_abschaltung.htm'>MSXFAQ: Kerberos RC4 Abschaltung (Frank Carius)</a>")
    $h.Bullet("<a href='https://borncity.com/blog/2026/01/20/windows-januar-2026-updates-bereiten-rc4-abschaltung-vor/'>Borns IT-Blog: Januar 2026 Updates / RC4-Abschaltung</a>")
    $h.Bullet("<a href='https://www.heise.de/news/Microsoft-Erinnerung-an-naechste-Phase-der-Kerberos-RC4-Haertung-11217286.html'>heise: Microsoft-Erinnerung an Kerberos-RC4-Haertung</a>")

    $h.Spacer()
    $h.AppendLine("<div class='dg-footer'><span>RC4 Risikobewertung — ${DomainLabel}</span><span>Stichtag: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</span></div>")

    # ═══════════════════════════════════════════════════════════════
    # SAVE
    # ═══════════════════════════════════════════════════════════════

    if (-not $OutputPath) {
        $OutputPath = Join-Path $ReportPath "RC4_${DomainLabel}_Risikobewertung.html"
    }

    $doc.Save($OutputPath)
    Write-Host "`n  Im Browser oeffnen und als PDF drucken (Strg+P)." -ForegroundColor DarkGray
    Write-Host ""
}
#endregion

#region ============ MODUS: COMPARE (Baseline-Diff ueber alle Server) ============

# Vergleicht zwei Readiness-Reports (SMB_Kerberos_report_*.csv) und akkumuliert
# pro Einstellung, was sich zwischen Vorher und Nachher geaendert hat — ueber
# ALLE Server. Beantwortet: "Was hat das Update umgestellt?"
# Kein AD, kein WinRM, keine Events — reine CSV-Auswertung. Strict-safe.
function Invoke-ModeCompare {
    Set-StrictMode -Version 2

    $settingCols = @('SMB_Server_Require','SMB_Client_Require','Kerb_EncTypes','Kerb_Source',
                     'LDAP_ServerIntegrity','LDAP_ChannelBinding','NTLM_Restrict',
                     'OSBuild','IsServer2025','RiskLevel')

    function Resolve-ReportCsv {
        param([string]$P, [string]$Label)
        if (-not $P) { return $null }
        $hits = @(Get-ChildItem -Path $P -File -EA SilentlyContinue |
                  Where-Object { $_.Name -notmatch '_KerberosAudit|_recommendations|_urgent_fix' })
        if ($hits.Count -eq 0) { Write-Host "  FEHLER ($Label): keine Datei unter $P" -ForegroundColor Red; return $null }
        if ($hits.Count -gt 1) {
            Write-Host "  $Label — mehrere Treffer, nehme neueste:" -ForegroundColor Yellow
            $hits | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor DarkGray }
            $hits = @($hits | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        }
        return $hits[0].FullName
    }

    $beforeCsv = Resolve-ReportCsv $CompareBefore 'Vorher'
    $afterCsv  = Resolve-ReportCsv $CompareAfter  'Nachher'

    # Auto-Erkennung: ohne -CompareBefore/-CompareAfter aeltester+neuester Hauptreport aus ReportPath
    if (-not $beforeCsv -or -not $afterCsv) {
        $auto = @(Get-ChildItem -Path (Join-Path $ReportPath 'SMB_Kerberos_report_*.csv') -File -EA SilentlyContinue |
                  Where-Object { $_.Name -notmatch '_KerberosAudit|_recommendations|_urgent_fix' } |
                  Sort-Object LastWriteTime)
        if ($auto.Count -lt 2) {
            Write-Host "`n  FEHLER: -Mode Compare benoetigt -CompareBefore/-CompareAfter oder" -ForegroundColor Red
            Write-Host "  mindestens zwei SMB_Kerberos_report_*.csv unter $ReportPath." -ForegroundColor Red
            return
        }
        $beforeCsv = $auto[0].FullName
        $afterCsv  = $auto[$auto.Count-1].FullName
        Write-Host "  Auto-Auswahl aus ${ReportPath}:" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  Vorher : $beforeCsv" -ForegroundColor White
    Write-Host "  Nachher: $afterCsv" -ForegroundColor White

    $before = @(Import-Csv -Path $beforeCsv -Delimiter ';')
    $after  = @(Import-Csv -Path $afterCsv  -Delimiter ';')
    Write-Host ("  Server: {0} vorher | {1} nachher" -f $before.Count, $after.Count) -ForegroundColor White

    # Index nach ComputerName (O(1)-Join)
    $bIdx = @{}; foreach ($r in $before) { $bIdx[[string]$r.ComputerName] = $r }
    $aIdx = @{}; foreach ($r in $after)  { $aIdx[[string]$r.ComputerName] = $r }

    function Get-Col { param($Row, [string]$Name)
        $p = $Row.PSObject.Properties[$Name]
        if ($p) { [string]$p.Value } else { '' }
    }

    $diffs = New-Object System.Collections.Generic.List[PSObject]
    foreach ($name in ($bIdx.Keys | Sort-Object)) {
        if (-not $aIdx.ContainsKey($name)) {
            $diffs.Add([PSCustomObject]@{ ComputerName=$name; Einstellung='(Server)'; Vorher='vorhanden'; Nachher='FEHLT im Nachher-Report' })
            continue
        }
        $b = $bIdx[$name]; $a = $aIdx[$name]
        foreach ($col in $settingCols) {
            $vb = Get-Col $b $col; $va = Get-Col $a $col
            if ($vb -ne $va) {
                $diffs.Add([PSCustomObject]@{ ComputerName=$name; Einstellung=$col; Vorher=$vb; Nachher=$va })
            }
        }
    }
    foreach ($name in ($aIdx.Keys | Sort-Object)) {
        if (-not $bIdx.ContainsKey($name)) {
            $diffs.Add([PSCustomObject]@{ ComputerName=$name; Einstellung='(Server)'; Vorher='FEHLT im Vorher-Report'; Nachher='vorhanden' })
        }
    }

    Write-Host ""
    Write-Host "=== AKKUMULIERT: WAS HAT SICH GEAENDERT? ===" -ForegroundColor Yellow
    if ($diffs.Count -eq 0) {
        Write-Host "  Keine Aenderung an den ueberwachten Einstellungen — das Update hat nichts umgestellt." -ForegroundColor Green
    } else {
        $grouped = @($diffs | Group-Object Einstellung, Vorher, Nachher | Sort-Object Count -Descending)
        foreach ($g in $grouped) {
            $ex = $g.Group[0]
            $servers = @($g.Group | ForEach-Object { $_.ComputerName } | Sort-Object)
            $show = ($servers | Select-Object -First 10) -join ', '
            if ($servers.Count -gt 10) { $show += " (+$($servers.Count-10) weitere)" }
            $color = if ($ex.Einstellung -in @('OSBuild','IsServer2025')) { 'Cyan' }
                     elseif ($ex.Einstellung -eq '(Server)') { 'Yellow' } else { 'Red' }
            Write-Host ("  [{0,3}x] {1}: '{2}' -> '{3}'" -f $g.Count, $ex.Einstellung, $ex.Vorher, $ex.Nachher) -ForegroundColor $color
            Write-Host ("         {0}" -f $show) -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host ("  Gesamt: {0} Aenderungen auf {1} Servern" -f $diffs.Count, (@($diffs | Select-Object -ExpandProperty ComputerName -Unique).Count)) -ForegroundColor White
        Write-Host "  Hinweis: OSBuild/IsServer2025 = Patch-Evidenz (erwartet, cyan). Rot = stille Umstellung durch das Update." -ForegroundColor DarkGray
    }

    $outDir = $ReportPath
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    if ($diffs.Count -gt 0) {
        $diffCsv = Join-Path $outDir "SMB_Kerberos_Diff_${ts}.csv"
        $diffs | Export-Csv -Path $diffCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host ""
        Write-Host "  Diff-CSV: $diffCsv ($($diffs.Count) Zeilen)" -ForegroundColor Green
    }
}

#endregion

#region ============ MAIN ============

function Invoke-ModeReport {
    if (-not $ReportSource) {
        Write-Host "`n  FEHLER: -Mode Report benoetigt -ReportSource <Ordner mit CSVs>." -ForegroundColor Red
        return
    }
    if (-not (Test-Path $ReportSource)) {
        Write-Host "`n  FEHLER: ReportSource nicht gefunden: $ReportSource" -ForegroundColor Red
        return
    }
    if ($ReportStyle -eq 'DG') { Invoke-ReportDG } else { Invoke-ReportPlain }
}

if ($ImportOnly -or $MyInvocation.InvocationName -eq '.') {
    Write-Host ""
    Write-Host "  Invoke-RC4Audit v1.0 — Funktionen geladen (ImportOnly)" -ForegroundColor Cyan
    Write-Host "  Modi:   Invoke-ModeReadiness  Invoke-ModeProve  Invoke-ModeDiscover  Invoke-ModeReport  Invoke-ModeCompare" -ForegroundColor DarkGray
    Write-Host "  Basis:  Discover-Helfer (SafeCount, Get-EncLabel, Get-XmlField, Get-EncCategory, ...)" -ForegroundColor DarkGray
    Write-Host "  Report: Invoke-ReportPlain  Invoke-ReportDG (Klassen DGColor/DGHtml/DGDocument)" -ForegroundColor DarkGray
    Write-Host ""
    return
}

Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "   RC4/Kerberos-Audit v1.0 — Modus: $Mode" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan

$script:LastRC4ReportDir = $null

switch ($Mode) {
    'Readiness' { Invoke-ModeReadiness }
    'Prove'     { Invoke-ModeProve }
    'Discover'  { Invoke-ModeDiscover }
    'Report'    { Invoke-ModeReport }
    'Compare'   { Invoke-ModeCompare }
    'Full'      {
        Invoke-ModeReadiness
        Invoke-ModeProve
        Invoke-ModeDiscover
        if ($script:LastRC4ReportDir -and (Test-Path $script:LastRC4ReportDir)) {
            $ReportSource = $script:LastRC4ReportDir
            Invoke-ModeReport
        } else {
            Write-Host "`n  Kein Discover-Ergebnisordner — Report uebersprungen." -ForegroundColor Yellow
        }
    }
}

#endregion
