#Requires -Version 5.1
<#
.SYNOPSIS
    Prueft ob RC4 Kerberos aktiv in der Umgebung verwendet wird.
    Auf einem DC ausfuehren um RC4-Nutzung nachzuweisen.

.DESCRIPTION
    Verwendet FilterXML (serverseitige Filterung) und XML-Parsing statt
    FilterHashtable + Where-Object + Message Regex. Windows filtert VOR
    der Rueckgabe — deutlich schneller auf ausgelasteten DCs.

    Acht Pruefungen:
    1.  Event 4768 (TGT) mit TicketEncryptionType=0x17 (RC4)
    2.  Event 4769 (Service Ticket) mit TicketEncryptionType=0x17 (RC4)
    3.  Event 14/4 (Kerberos EncType Fehler)
    3b. Event 4770 (Ticket Renewal mit RC4 — Cache-Verlaengerung)
    3c. Event 4771 (Kerberos Pre-Auth Failed — Beginn Fallback-Kette)
    5.  Event 4625/4740 (NTLM Fallback + Lockout-Korrelation)
    6.  Event 2887/2889/3039 (LDAP Signing + Channel Binding)
    7.  AD-Account Verschluesselungstypen (msDS-SupportedEncryptionTypes)

    Performance:
    - FilterXML: Windows Event Engine filtert, nicht PowerShell
    - MaxEvents: begrenzt Ergebnisse, liest nie das gesamte Log
    - XML-Parsing: [xml]$evt.ToXml() statt String-Regex auf Message
    - wevtutil Fallback: noch schneller fuer einfache Zaehlung

.PARAMETER Hours
    How many hours back to search. Default: 24

.PARAMETER MaxEvents
    Max events to return per check. Default: 500

.PARAMETER ExportPath
    Export results to CSV files. Default: C:\Temp

.PARAMETER CountOnly
    Fast mode: only count RC4 events, don't parse details. Uses wevtutil.

.EXAMPLE
    .\Prove-RC4Usage.ps1                         # last 24h, max 500 events
    .\Prove-RC4Usage.ps1 -Hours 72 -MaxEvents 1000
    .\Prove-RC4Usage.ps1 -CountOnly              # fastest: just counts
    .\Prove-RC4Usage.ps1 -Hours 168              # last 7 days

.NOTES
    Datum   : 2026-03-09
    Version : 3.0
    Ref     : https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
              https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/
              https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 500,
    [string]$ExportPath = 'C:\Temp',
    [switch]$CountOnly
)

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
$xmlErr14 = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[(EventID=14) and TimeCreated[timediff(@SystemTime) &lt;= MSBACK_PLACEHOLDER]]]</Select></Query></QueryList>'.Replace('MSBACK_PLACEHOLDER', $msBack)

Write-Host "  Event 14 (KDC_ERR_ETYPE_NOSUPP)..." -NoNewline
$evt14 = @()
try {
    $evt14 = Get-WinEvent -FilterXml $xmlErr14 -MaxEvents 50 -EA Stop
    Write-Host " $($evt14.Count) errors!" -ForegroundColor Red
    foreach ($e in ($evt14 | Select-Object -First 3)) {
        $x = [xml]$e.ToXml()
        Write-Host "    $($e.TimeCreated): $($e.Message.Substring(0, [math]::Min(120, $e.Message.Length)))..." -ForegroundColor Red
    }
    if ($evt14.Count -gt 3) { Write-Host "    ... and $($evt14.Count - 3) more" -ForegroundColor Red }
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
    $evt4 = Get-WinEvent -FilterXml $xmlErr4 -MaxEvents 50 -EA Stop
    Write-Host " $($evt4.Count) errors!" -ForegroundColor Red
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
    $rawPreAuth = Get-WinEvent -FilterXml $xmlPreAuth -MaxEvents $MaxEvents -EA Stop
    Write-Host " $($rawPreAuth.Count) Fehler" -ForegroundColor $(if ($rawPreAuth.Count -gt 50) {'Red'} elseif ($rawPreAuth.Count -gt 0) {'Yellow'} else {'Green'})
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
    $rawLogonFail = Get-WinEvent -FilterXml $xmlLogonFail -MaxEvents $MaxEvents -EA Stop
    Write-Host " $($rawLogonFail.Count)" -ForegroundColor $(if ($rawLogonFail.Count -gt 100) {'Red'} elseif ($rawLogonFail.Count -gt 0) {'Yellow'} else {'Green'})
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
    $rawLockout = Get-WinEvent -FilterXml $xmlLockout -MaxEvents $MaxEvents -EA Stop
    Write-Host " $($rawLockout.Count)" -ForegroundColor $(if ($rawLockout.Count -gt 20) {'Red'} elseif ($rawLockout.Count -gt 0) {'Yellow'} else {'Green'})
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
    $rc4Comp = Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
        Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 }
    Write-Host " $($rc4Comp.Count)" -ForegroundColor $(if ($rc4Comp.Count -gt 0) {'Yellow'} else {'Green'})

    Write-Host "  RC4-ONLY computers (will break)..." -NoNewline
    $rc4Only = $rc4Comp | Where-Object { -not ($_.'msDS-SupportedEncryptionTypes' -band 0x18) }
    Write-Host " $($rc4Only.Count)" -ForegroundColor $(if ($rc4Only.Count -gt 0) {'Red'} else {'Green'})

    Write-Host "  gMSAs with RC4..." -NoNewline
    $rc4gMSA = Get-ADServiceAccount -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
        Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 0x4 }
    Write-Host " $($rc4gMSA.Count)" -ForegroundColor $(if ($rc4gMSA.Count -gt 0) {'Yellow'} else {'Green'})

    Write-Host "  Trusts without AES..." -NoNewline
    $domDN = (Get-ADDomain).DistinguishedName
    $trusts = Get-ADObject -SearchBase "CN=System,$domDN" -LDAPFilter '(objectClass=trustedDomain)' `
        -Properties 'msDS-SupportedEncryptionTypes'
    $rc4Trusts = $trusts | Where-Object {
        $e = $_.'msDS-SupportedEncryptionTypes'; $null -eq $e -or $e -eq 0 -or ($e -band 0x4 -and -not ($e -band 0x18))
    }
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
