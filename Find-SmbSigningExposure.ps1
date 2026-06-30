#Requires -Version 5.1
<#
.SYNOPSIS
    Sammelt nach aktivem SMB-Signing-Audit die "Positiv"-Events
    (Microsoft-Windows-SMBServer/Audit, IDs 3021/3027, optional EPA 3024-3026)
    und liefert eine deduplizierte Liste betroffener Clients — damit der Kunde
    inkompatible Geraete remediiert, BEVOR das DC-Update das Hardening erzwingt.

.DESCRIPTION
    Analog zu Find-CBTExposure.ps1, jedoch fuer SMB Server Signing.

    Voraussetzung: Audit ist aktiv (AuditClientDoesNotSupportSigning = 1).
    Status pruefbar mit Get-SmbSigningPosture.ps1.

    Je Zielsystem (DCs/Fileserver) werden die Audit-Events ausgelesen:
      3021  SMB2/3 — Client unterstuetzt kein Signing        (zuverlaessig)
      3027  SMB1   — SMBv1-Client ohne Signing               (unzuverlaessig, MS-Hinweis)
      3024  EPA    — Client sendet keinen SPN       (nur mit -IncludeEpa)
      3025  EPA    — Client sendet unbekannten SPN  (nur mit -IncludeEpa)
      3026  EPA    — Client sendet leeren SPN       (nur mit -IncludeEpa)
      3000  SMB1   — SMB1-Zugriffsversuch (Protokoll genutzt) (nur mit -IncludeSmb1Access)

    Feld-Extraktion erfolgt ueber die EventData-XML (sprachneutral), NICHT ueber
    den gerenderten Meldungstext — Kundensysteme sind deutschsprachig, dort waeren
    die Labels uebersetzt. Die Feldzuordnung ist defensiv (Name-Attribut bevorzugt,
    sonst Position). Mit -ShowSample wird das erste Roh-Event (XML + Meldung)
    ausgegeben, um die Zuordnung in der Umgebung zu verifizieren.

    Ergebnis:
      - SMBSigning_Exposure_Raw.csv             ein Datensatz je Event
      - SMBSigning_Exposure_AffectedClients.csv dedupliziert — die Remediations-Liste

.PARAMETER TargetScope
    DiscoveredOnly (Standard: Domain Controller), AllServers oder Full.

.PARAMETER ComputerName
    Explizite Zielliste. Ueberschreibt die TargetScope-Discovery.

.PARAMETER Hours
    Rueckblick-Zeitraum in Stunden. Standard 168 (7 Tage).
    Fuer monatliche Jobs/Backups das Fenster entsprechend vergroessern.

.PARAMETER MaxEvents
    Maximale Events je System. Standard 5000.

.PARAMETER IncludeEpa
    Zusaetzlich EPA-Events 3024/3025/3026 sammeln.

.PARAMETER ExcludeSmb1
    Event 3027 (SMBv1-Signing) auslassen.

.PARAMETER IncludeSmb1Access
    Zusaetzlich Event 3000 (SMB1-Zugriffsversuch) sammeln. Benoetigt separates
    Audit (AuditSmb1Access).

.PARAMETER ReportPath
    Zielordner. Standard C:\Temp

.PARAMETER SkipRemoteCheck
    Nur lokales System.

.PARAMETER ShowSample
    Erstes Roh-Event (XML + gerenderte Meldung) zur Feld-Verifikation ausgeben.

.PARAMETER ImportOnly
    Nur Funktionen laden, kein Scan.

.EXAMPLE
    .\Find-SmbSigningExposure.ps1
    .\Find-SmbSigningExposure.ps1 -TargetScope AllServers -Hours 336
    .\Find-SmbSigningExposure.ps1 -ComputerName DC01,DC02 -IncludeEpa
    .\Find-SmbSigningExposure.ps1 -SkipRemoteCheck -IncludeEpa -IncludeSmb1Access
    .\Find-SmbSigningExposure.ps1 -SkipRemoteCheck -ShowSample

.NOTES
    Version  : 1.1
    Kontext  : SMB Server Signing Hardening — Betroffene VOR Enforcement finden
    Referenz : KB5066913 (CVE-2025-55234)
    Log      : Microsoft-Windows-SMBServer/Audit
    Schalter : Drei getrennte Audit-Schalter, drei Kategorien:
               Signing -> AuditClientDoesNotSupportSigning  -> 3021/3027
               EPA     -> AuditClientSpnSupport             -> 3024/3025/3026
               SMB1    -> AuditSmb1Access                   -> 3000
    Hinweise : 3027/SMBv1 ist laut Microsoft nicht eindeutig (False Positives/Negatives).
               Client signiert, kuendigt es aber nicht an   -> False Positive.
               Client kuendigt Signing an, kann es aber nicht -> False Negative.
               EPA (3024-3026) ist KEIN Signing-Problem: SPN/DNS pruefen, kein Firmware-Thema.
    Voraussetzung: Audit aktiv (Get-SmbSigningPosture.ps1 zur Pruefung).
#>

[CmdletBinding()]
param(
    [ValidateSet('DiscoveredOnly','AllServers','Full')]
    [string]$TargetScope = 'DiscoveredOnly',
    [string[]]$ComputerName,
    [int]$Hours = 168,
    [int]$MaxEvents = 5000,
    [switch]$IncludeEpa,
    [switch]$ExcludeSmb1,
    [switch]$IncludeSmb1Access,
    [string]$ReportPath = 'C:\Temp',
    [switch]$SkipRemoteCheck,
    [switch]$ShowSample,
    [switch]$ImportOnly
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'

$domainFQDN = $env:USERDNSDOMAIN
if (-not $domainFQDN) {
    try { $domainFQDN = (Get-ADDomain -EA Stop).DNSRoot } catch { $domainFQDN = 'UNKNOWN' }
}
$domainShort = ($domainFQDN -split '\.')[0]
$reportDir = Join-Path $ReportPath "SMBExpo_${domainShort}_${ts}"

#region ============ HELPERS ============

function SafeCount { param($C) if ($null -eq $C) {0} elseif ($C -is [array]) {$C.Length} else {1} }

# Holt einen EventData-Wert: erst per Name-Kandidaten, dann per Position.
# Robust gegen beide PowerShell-Repraesentationen der Data-Knoten:
#   - mit Name-Attribut  -> XmlElement (Name/InnerText nutzbar)
#   - ohne Name-Attribut -> kollabiert zu reinem String (kein '#text'/Name)
function Get-EvField {
    param($DataNodes, [string[]]$Names, [int]$Index = -1)
    $arr = @($DataNodes)

    # Named (nur moeglich, wenn die Knoten Name-Attribute tragen)
    foreach ($n in $Names) {
        foreach ($node in $arr) {
            try {
                if ($node -isnot [string]) {
                    if (([string]$node.Name) -eq $n) {
                        $txt = [string]$node.InnerText
                        if ($txt -ne '') { return $txt }
                    }
                }
            } catch {}
        }
    }

    # Positional (Fallback) — haelt String und XmlElement aus
    if ($Index -ge 0 -and $arr.Count -gt $Index) {
        try {
            $node = $arr[$Index]
            $val  = if ($node -is [string]) { $node } else { [string]$node.InnerText }
            if ($null -ne $val -and "$val" -ne '') { return [string]$val }
        } catch {}
    }
    return ''
}

function Get-EventIdMeaning {
    param([int]$Id)
    switch ($Id) {
        3000 { 'SMB1: Zugriffsversuch (SMB1-Protokoll genutzt)' }
        3021 { 'SMB2/3: Client unterstuetzt kein Signing' }
        3027 { 'SMB1: SMBv1-Client ohne Signing (unzuverlaessig)' }
        3024 { 'EPA: kein SPN gesendet' }
        3025 { 'EPA: unbekannter SPN' }
        3026 { 'EPA: leerer SPN' }
        default { "Event $Id" }
    }
}

# Drei Kategorien = drei getrennte Audit-Schalter / drei Remediations-Pfade.
function Get-EventCategory {
    param([int]$Id)
    switch ($Id) {
        3000 { 'SMB1-Access' }
        3021 { 'Signing' }
        3027 { 'Signing' }
        3024 { 'EPA' }
        3025 { 'EPA' }
        3026 { 'EPA' }
        default { 'Sonstige' }
    }
}

# Kategorie-spezifische Handlungsempfehlung (ein Client kann mehrere Kategorien treffen).
function Get-CategoryBewertung {
    param([int[]]$EventIds)
    $cats  = @($EventIds | ForEach-Object { Get-EventCategory $_ } | Sort-Object -Unique)
    $parts = @()
    if ($cats -contains 'Signing')     { $parts += 'Signing: bei RequireSecuritySignature-Enforcement betroffen. Client-Signing aktivieren / SMB-Version / Firmware.' }
    if ($cats -contains 'EPA')         { $parts += 'EPA: SPN-Mismatch, kein Signing-Problem. SPN/DNS pruefen (z.B. veralteter/aliasierter Servername), kein Firmware-Thema.' }
    if ($cats -contains 'SMB1-Access') { $parts += 'SMB1: Protokoll im Einsatz. Bei SMB1-Deaktivierung betroffen. SMB1 am Client abschalten / Client modernisieren.' }
    if ($parts.Count -eq 0) { $parts += 'Pruefen.' }
    return ($parts -join ' | ')
}

#endregion

#region ============ DISCOVERY ============

function Get-TargetServers {
    [CmdletBinding()]
    param([string]$TargetScope)

    Write-Host "`n=== SERVER DISCOVERY ($TargetScope) ===" -ForegroundColor Cyan
    $list = @()
    try {
        switch ($TargetScope) {
            'DiscoveredOnly' {
                foreach ($d in @(Get-ADDomainController -Filter * -EA Stop)) {
                    $list += [PSCustomObject]@{ DNSHostName = $d.HostName; Name = $d.Name; Role = 'DC' }
                }
            }
            'AllServers' {
                $cs = @(Get-ADComputer -Filter "OperatingSystem -like '*Server*'" -Properties DNSHostName,userAccountControl -EA Stop |
                        Where-Object { $_.Enabled -ne $false })
                foreach ($c in $cs) {
                    $isDc = [bool]([int]($c.userAccountControl) -band 8192)
                    $list += [PSCustomObject]@{ DNSHostName = $c.DNSHostName; Name = $c.Name; Role = if ($isDc) {'DC'} else {'Server'} }
                }
            }
            'Full' {
                $cs = @(Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem,userAccountControl -EA Stop |
                        Where-Object { $_.Enabled -ne $false })
                foreach ($c in $cs) {
                    $isDc = [bool]([int]($c.userAccountControl) -band 8192)
                    $os   = "$($c.OperatingSystem)"
                    $role = if ($isDc) {'DC'} elseif ($os -like '*Server*') {'Server'} else {'Workstation'}
                    $list += [PSCustomObject]@{ DNSHostName = $c.DNSHostName; Name = $c.Name; Role = $role }
                }
            }
        }
    } catch {
        Write-Host "  AD-Discovery fehlgeschlagen: $_" -ForegroundColor Red
    }
    $list = @($list | Where-Object { $_.DNSHostName } | Sort-Object DNSHostName -Unique)
    Write-Host "  Ziel-Systeme: $(SafeCount $list)" -ForegroundColor Gray
    return $list
}

#endregion

#region ============ COLLECTION ============

function Get-SigningAuditEvents {
    param(
        [string]$Computer,
        [int[]]$Ids,
        [int]$Hours,
        [int]$MaxEvents,
        [bool]$Local,
        [bool]$ShowSample
    )

    $start  = (Get-Date).AddHours(-$Hours)
    $filter = @{ LogName = 'Microsoft-Windows-SMBServer/Audit'; Id = $Ids; StartTime = $start }

    $getParams = @{ FilterHashtable = $filter; MaxEvents = $MaxEvents; ErrorAction = 'Stop' }
    if (-not $Local) { $getParams['ComputerName'] = $Computer }

    $raw = @()
    try {
        $raw = @(Get-WinEvent @getParams)
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') { return @() }
        Write-Host "    Event-Abfrage Fehler ($Computer): $($_.Exception.Message)" -ForegroundColor DarkYellow
        return @()
    }

    if ($ShowSample -and $raw.Count -gt 0) {
        Write-Host "`n--- SAMPLE EVENT (Feld-Verifikation) ---" -ForegroundColor Magenta
        Write-Host $raw[0].Message -ForegroundColor Gray
        Write-Host ($raw[0].ToXml()) -ForegroundColor DarkGray
        Write-Host "--- ENDE SAMPLE ---`n" -ForegroundColor Magenta
    }

    $rows = @()
    foreach ($evt in $raw) {
        $id = [int]$evt.Id
        $data = $null
        try { $data = ([xml]$evt.ToXml()).Event.EventData.Data } catch {}

        $client = Get-EvField $data @('ClientName','Client','ClientAddress','ClientNameOrAddress') 0
        $user   = ''
        $reqSig = ''
        $detail = ''

        switch ($id) {
            3021 {
                $user   = Get-EvField $data @('UserName','User','TargetUserName') 1
                $reqSig = Get-EvField $data @('ServerSigningRequired','ServerRequiresSigning','RequireSigning','SigningRequired') 2
            }
            3027 {
                $reqSig = Get-EvField $data @('ServerSigningRequired','ServerRequiresSigning','RequireSigning','SigningRequired') 1
            }
            3024 { $detail = Get-EvField $data @('SpnQueryStatus','Status') 1 }
            3025 { $detail = Get-EvField $data @('Spn','SPN','ServicePrincipalName') 1 }
            3026 { $detail = 'leerer SPN' }
            3000 { }   # nur Client Address (bereits in $client)
        }

        $reliability = if ($id -eq 3027) { 'SMBv1 — unzuverlaessig (verifizieren)' } else { 'OK' }

        $rows += [PSCustomObject][ordered]@{
            Server         = $Computer
            TimeCreated    = $evt.TimeCreated
            EventId        = $id
            Kategorie      = Get-EventCategory $id
            Bedeutung      = Get-EventIdMeaning $id
            ClientName     = $client
            UserName       = $user
            Detail         = $detail
            ServerRequires = $reqSig
            Reliability    = $reliability
            Message        = ($evt.Message -replace '\s+', ' ').Trim()
        }
    }
    return $rows
}

function Get-AffectedClientSummary {
    param([array]$Rows)

    $groups = $Rows | Where-Object { $_.ClientName -and $_.ClientName -ne '' } |
              Group-Object { $_.ClientName.ToLower() }

    $summary = foreach ($g in $groups) {
        $items    = @($g.Group)
        $eventIds = @($items.EventId | Sort-Object -Unique)
        $ids      = $eventIds -join ','
        $cats     = @($eventIds | ForEach-Object { Get-EventCategory $_ } | Sort-Object -Unique) -join ','
        $servers  = @($items.Server | Sort-Object -Unique) -join ','

        # repraesentatives Detail (SPN bei EPA, sonst User bei Signing)
        $detItems = @($items | Where-Object { $_.Detail   -and $_.Detail   -ne '' } | Select-Object -ExpandProperty Detail   -Unique)
        $usrItems = @($items | Where-Object { $_.UserName -and $_.UserName -ne '' } | Select-Object -ExpandProperty UserName -Unique)
        $detail   = if ($detItems.Count -gt 0) { $detItems -join ' / ' } elseif ($usrItems.Count -gt 0) { $usrItems[0] } else { '' }

        # unsicher nur, wenn ausschliesslich 3027 (SMBv1-Signing)
        $non3027  = @($eventIds | Where-Object { $_ -ne 3027 }).Count
        $relWorst = if (($eventIds -contains 3027) -and $non3027 -eq 0) { 'SMBv1 — unzuverlaessig (verifizieren)' } else { 'OK' }

        # 3021 = bei Signing-Enforcement sicher blockiert -> Fehler; sonst (EPA/SMB1/3027) Warnung
        $severity = if ($eventIds -contains 3021) { 'Fehler' } else { 'Warnung' }

        [PSCustomObject][ordered]@{
            ClientName  = $items[0].ClientName
            Kategorien  = $cats
            EventIds    = $ids
            Count       = $items.Count
            FirstSeen   = ($items.TimeCreated | Sort-Object | Select-Object -First 1)
            LastSeen    = ($items.TimeCreated | Sort-Object | Select-Object -Last 1)
            ObservedOn  = $servers
            Detail      = $detail
            Reliability = $relWorst
            Severity    = $severity
            Bewertung   = (Get-CategoryBewertung $eventIds)
        }
    }
    return @($summary | Sort-Object @{E='Severity';Descending=$false}, @{E='Count';Descending=$true})
}

#endregion

#region ============ REPORT ============

function Export-ExposureReport {
    param([array]$Raw, [array]$Summary, [string]$Path)

    if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }

    if ((SafeCount $Raw) -gt 0) {
        $Raw | Export-Csv (Join-Path $Path 'SMBSigning_Exposure_Raw.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: SMBSigning_Exposure_Raw.csv ($(SafeCount $Raw))" -ForegroundColor Green
    }
    if ((SafeCount $Summary) -gt 0) {
        $Summary | Export-Csv (Join-Path $Path 'SMBSigning_Exposure_AffectedClients.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: SMBSigning_Exposure_AffectedClients.csv ($(SafeCount $Summary))" -ForegroundColor Green
    }

    $hasExcel = $false
    try { Import-Module ImportExcel -EA Stop; $hasExcel = $true } catch {}
    if ($hasExcel) {
        $xl = Join-Path $Path "SMBSigning_${domainShort}_Exposure.xlsx"
        $ctRel = @(
            (New-ConditionalText 'Fehler'  -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'Warnung' -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            (New-ConditionalText 'OK'      -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
        )
        if ((SafeCount $Summary) -gt 0) {
            $Summary | Export-Excel -Path $xl -WorksheetName 'AffectedClients' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $ctRel
        }
        if ((SafeCount $Raw) -gt 0) {
            $Raw | Export-Excel -Path $xl -WorksheetName 'RawEvents' -AutoSize -FreezeTopRow -BoldTopRow -Append
        }
        Write-Host "  Excel: $xl" -ForegroundColor Green
    }

    $zip = "${Path}.zip"
    try {
        Compress-Archive -Path "$Path\*" -DestinationPath $zip -Force -EA Stop
        Write-Host "  ZIP: $zip" -ForegroundColor Green
    } catch { Write-Host "  ZIP fehlgeschlagen: $_" -ForegroundColor DarkGray }
}

#endregion

#region ============ MAIN ============

$script:_IsDotSourced = $false
try {
    if ($MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -match '^\.\s') {
        $script:_IsDotSourced = $true
    }
} catch {}

if ($ImportOnly) {
    Write-Host "  Funktionen geladen (-ImportOnly). Kein Scan." -ForegroundColor Cyan
    Write-Host "    Get-TargetServers  Get-SigningAuditEvents  Get-AffectedClientSummary  Export-ExposureReport" -ForegroundColor DarkGray
}
elseif (-not $script:_IsDotSourced) {

    $ids = @(3021)
    if (-not $ExcludeSmb1)   { $ids += 3027 }
    if ($IncludeEpa)         { $ids += 3024,3025,3026 }
    if ($IncludeSmb1Access)  { $ids += 3000 }
    $ids = @($ids | Sort-Object -Unique)

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  SMB Signing Exposure v1.1  (Betroffene vor Enforcement)" -ForegroundColor Cyan
    Write-Host "  Domaene: $domainFQDN ($domainShort)" -ForegroundColor Cyan
    Write-Host "  Scope: $TargetScope | Fenster: $Hours h | Event-IDs: $($ids -join ',')" -ForegroundColor Cyan
    Write-Host "  Report: $reportDir" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    $targets = @()
    if ($ComputerName) {
        $targets = @($ComputerName | ForEach-Object { [PSCustomObject]@{ DNSHostName = $_; Name = $_; Role = 'Explizit' } })
    } elseif ($SkipRemoteCheck) {
        $targets = @([PSCustomObject]@{ DNSHostName = $env:COMPUTERNAME; Name = $env:COMPUTERNAME; Role = 'Lokal' })
    } else {
        $targets = Get-TargetServers -TargetScope $TargetScope
        if (-not ($targets.DNSHostName -contains $env:COMPUTERNAME)) {
            $targets = @([PSCustomObject]@{ DNSHostName = $env:COMPUTERNAME; Name = $env:COMPUTERNAME; Role = 'Lokal' }) + $targets
        }
    }

    $allRaw = @()
    $sampleShown = $false
    $i = 0
    foreach ($t in $targets) {
        $i++
        $c = $t.DNSHostName
        Write-Host ("`n[{0}/{1}] {2}" -f $i, (SafeCount $targets), $c) -ForegroundColor Cyan
        $isLocal  = ($c -eq $env:COMPUTERNAME) -or ($c -eq 'localhost') -or ($c -eq '.')
        $doSample = ($ShowSample -and -not $sampleShown)
        $rows = Get-SigningAuditEvents -Computer $c -Ids $ids -Hours $Hours -MaxEvents $MaxEvents -Local ($isLocal -or $SkipRemoteCheck) -ShowSample $doSample
        if ($doSample -and (SafeCount $rows) -gt 0) { $sampleShown = $true }
        Write-Host ("    Events: {0}" -f (SafeCount $rows)) -ForegroundColor Gray
        $allRaw += $rows
    }

    $summary = Get-AffectedClientSummary -Rows $allRaw

    Write-Host "`n=== BETROFFENE CLIENTS ===" -ForegroundColor Cyan
    if ((SafeCount $summary) -gt 0) {
        $summary | Format-Table ClientName, Kategorien, EventIds, Count, LastSeen, Severity -AutoSize
        $fehler = @($summary | Where-Object { $_.Severity -eq 'Fehler'  }).Count
        $warn   = @($summary | Where-Object { $_.Severity -eq 'Warnung' }).Count
        Write-Host ("  {0} eindeutige Clients mit Audit-Treffern ({1} Fehler, {2} Warnung). Kategorien beachten — EPA ist kein Signing-Problem." -f (SafeCount $summary), $fehler, $warn) -ForegroundColor Yellow
    } else {
        Write-Host "  Keine Treffer im Zeitraum." -ForegroundColor Green
        Write-Host "  Pruefen: (1) Audit aktiv? -> Get-SmbSigningPosture.ps1   (2) Fenster (-Hours) gross genug?" -ForegroundColor DarkGray
    }

    Export-ExposureReport -Raw $allRaw -Summary $summary -Path $reportDir

    Write-Host "`nFertig." -ForegroundColor Cyan
}

#endregion
