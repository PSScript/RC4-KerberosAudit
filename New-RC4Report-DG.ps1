#Requires -Version 5.1
<#
.SYNOPSIS
    RC4 Risikobewertung — DATAGROUP HTML Report Generator
.DESCRIPTION
    Erzeugt einen DATAGROUP-gebrandeten RC4-Risikobewertungs-Report als HTML
    aus den CSVs von Check-Server2025Defaults und Discover-RC4Environment.
    Oeffnen im Browser → Drucken als PDF.
    Keine externen Abhaengigkeiten — laeuft auf jedem Windows-System.
.PARAMETER ReportPath
    Ordner mit den CSVs (z.B. C:\Temp\RC4_CONTOSO_20260319_162051)
.PARAMETER OutputPath
    Zielpfad fuer die HTML-Datei. Standard: ReportPath\RC4_[domain]_Risikobewertung.html
.PARAMETER Author
    Autor des Reports.
.PARAMETER DomainLabel
    Anzeigename der Domaene. Wird aus dem Ordnernamen erkannt wenn nicht angegeben.
.EXAMPLE
    .\New-RC4Report-DG.ps1 -ReportPath 'C:\Temp\RC4_CONTOSO_20260319_162051'
    .\New-RC4Report-DG.ps1 -ReportPath 'C:\Temp\RC4_DGBRS_20260320_132801' -Author 'Max Mustermann'
.NOTES
    Version : 1.0
    Design  : DATAGROUP Corporate Design (identisch mit Betriebshandbuch / HealthReport)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReportPath,
    [string]$OutputPath,
    [string]$Author = "Jan Hübener",
    [string]$DomainLabel
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# ═══════════════════════════════════════════════════════════════
# DATAGROUP Design System — PowerShell Classes
# ═══════════════════════════════════════════════════════════════

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
    <div class='dg-header-left'>DATAGROUP</div>
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

Write-Host "`n=== DATAGROUP RC4 Report ===" -ForegroundColor Cyan
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
    "DATAGROUP  |  RC4 Risikobewertung  |  Vertraulich"
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
    @("Klassifikation:", "<span class='dg-warn-red'>Vertraulich</span>"),
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
$h.AppendLine("<div class='dg-footer'><span>DATAGROUP | RC4 Risikobewertung — ${DomainLabel}</span><span>Stichtag: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</span></div>")

# ═══════════════════════════════════════════════════════════════
# SAVE
# ═══════════════════════════════════════════════════════════════

if (-not $OutputPath) {
    $OutputPath = Join-Path $ReportPath "RC4_${DomainLabel}_Risikobewertung.html"
}

$doc.Save($OutputPath)
Write-Host "`n  Im Browser oeffnen und als PDF drucken (Strg+P)." -ForegroundColor DarkGray
Write-Host ""
