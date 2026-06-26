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
    Event 3027 (SMBv1) auslassen.

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
    .\Find-SmbSigningExposure.ps1 -SkipRemoteCheck -ShowSample

.NOTES
    Version  : 1.0
    Kontext  : SMB Server Signing Hardening — Betroffene VOR Enforcement finden
    Referenz : KB5066913 (CVE-2025-55234)
    Log      : Microsoft-Windows-SMBServer/Audit
    Hinweise : 3027/SMBv1 ist laut Microsoft nicht eindeutig (False Positives/Negatives).
               Client signiert, kuendigt es aber nicht an   -> False Positive.
               Client kuendigt Signing an, kann es aber nicht -> False Negative.
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
function Get-EvField {
    param($DataNodes, [string[]]$Names, [int]$Index = -1)
    foreach ($n in $Names) {
        try {
            $hit = $DataNodes | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            if ($null -ne $hit -and $null -ne $hit.'#text') { return [string]$hit.'#text' }
        } catch {}
    }
    if ($Index -ge 0) {
        try {
            $arr = @($DataNodes)
            if ($arr.Count -gt $Index) {
                $val = $arr[$Index].'#text'
                if ($null -ne $val) { return [string]$val }
            }
        } catch {}
    }
    return ''
}

function Get-EventIdMeaning {
    param([int]$Id)
    switch ($Id) {
        3021 { 'SMB2/3: Client unterstuetzt kein Signing' }
        3027 { 'SMB1: SMBv1-Client ohne Signing (unzuverlaessig)' }
        3024 { 'EPA: kein SPN gesendet' }
        3025 { 'EPA: unbekannter SPN' }
        3026 { 'EPA: leerer SPN' }
        default { "Event $Id" }
    }
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

        switch ($id) {
            3021 {
                $user   = Get-EvField $data @('UserName','User','TargetUserName') 1
                $reqSig = Get-EvField $data @('ServerSigningRequired','ServerRequiresSigning','RequireSigning','SigningRequired') 2
            }
            3027 {
                $reqSig = Get-EvField $data @('ServerSigningRequired','ServerRequiresSigning','RequireSigning','SigningRequired') 1
            }
            3024 { $user = Get-EvField $data @('SpnQueryStatus','Status') 1 }
            3025 { $user = Get-EvField $data @('Spn','SPN','ServicePrincipalName') 1 }
            3026 { $user = '' }
        }

        $reliability = if ($id -eq 3027) { 'SMBv1 — unzuverlaessig (verifizieren)' } else { 'OK' }

        $rows += [PSCustomObject][ordered]@{
            Server         = $Computer
            TimeCreated    = $evt.TimeCreated
            EventId        = $id
            Bedeutung      = Get-EventIdMeaning $id
            ClientName     = $client
            UserName       = $user
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
        $items   = @($g.Group)
        $ids     = @($items.EventId | Sort-Object -Unique) -join ','
        $servers = @($items.Server  | Sort-Object -Unique) -join ','
        $users   = @($items | Where-Object { $_.UserName -and $_.UserName -ne '' } | Select-Object -ExpandProperty UserName -Unique)
        $sample  = if ($users.Count -gt 0) { $users[0] } else { '' }

        $nonSmb1 = @($items.EventId | Where-Object { $_ -ne 3027 }).Count
        $relWorst = if (($items.EventId -contains 3027) -and $nonSmb1 -eq 0) {
            'SMBv1 — unzuverlaessig (verifizieren)'
        } else { 'OK' }

        $bewertung = if ($relWorst -ne 'OK') {
            'Warnung — nur SMBv1-Signal. Vor Remediation funktional verifizieren.'
        } else {
            'Fehler — wuerde bei Enforcement abgewiesen. Remediation noetig (Firmware/Config/SMB-Version).'
        }

        [PSCustomObject][ordered]@{
            ClientName  = $items[0].ClientName
            EventIds    = $ids
            Count       = $items.Count
            FirstSeen   = ($items.TimeCreated | Sort-Object | Select-Object -First 1)
            LastSeen    = ($items.TimeCreated | Sort-Object | Select-Object -Last 1)
            ObservedOn  = $servers
            SampleUser  = $sample
            Reliability = $relWorst
            Bewertung   = $bewertung
        }
    }
    return @($summary | Sort-Object @{E='Reliability';Descending=$false}, @{E='Count';Descending=$true})
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
    if (-not $ExcludeSmb1) { $ids += 3027 }
    if ($IncludeEpa)       { $ids += 3024,3025,3026 }
    $ids = @($ids | Sort-Object -Unique)

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  SMB Signing Exposure v1.0  (Betroffene vor Enforcement)" -ForegroundColor Cyan
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
        $summary | Format-Table ClientName, EventIds, Count, LastSeen, Reliability -AutoSize
        $hard = @($summary | Where-Object { $_.Reliability -eq 'OK' }).Count
        $soft = @($summary | Where-Object { $_.Reliability -ne 'OK' }).Count
        Write-Host ("  {0} eindeutige Clients wuerden bei Enforcement abgewiesen ({1} zuverlaessig, {2} nur SMBv1)." -f (SafeCount $summary), $hard, $soft) -ForegroundColor Yellow
    } else {
        Write-Host "  Keine Treffer im Zeitraum." -ForegroundColor Green
        Write-Host "  Pruefen: (1) Audit aktiv? -> Get-SmbSigningPosture.ps1   (2) Fenster (-Hours) gross genug?" -ForegroundColor DarkGray
    }

    Export-ExposureReport -Raw $allRaw -Summary $summary -Path $reportDir

    Write-Host "`nFertig." -ForegroundColor Cyan
}

#endregion
