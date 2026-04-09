#Requires -Version 5.1
<#
.SYNOPSIS
    Erkennt Server die nach 2026.01B durch Channel Binding Token (CBT) Enforcement
    betroffen sein koennten (STATUS_BAD_BINDINGS / HTTP 401).

.DESCRIPTION
    Prueft alle Server in der Domaene auf:
    - DefaultAuthHardeningLevel Registry-Wert (HTTP.sys CBT)
    - IIS-Sites mit Windows Integrated Authentication
    - WinRM HTTPS-Listener
    - HTTP.sys URL-Reservierungen (Drittanbieter wie Apache/SSPI)
    - 2026.01B Patch-Status
    - TLS-Terminierung Indikatoren (Kemp, NetScaler, F5 Service Accounts)

    Kein Zusammenhang mit RC4/CVE-2026-20833 — das ist ein separates Problem
    in derselben Kerberos-Schicht, mit denselben Symptomen (401), aber
    unterschiedlicher Ursache und unterschiedlicher Mitigation.

.PARAMETER TargetScope
    DiscoveredOnly (Standard: nur IIS/Exchange/Citrix/ADFS/Web), AllServers oder Full.

.PARAMETER Hours
    Zeitraum fuer Event-Log-Suche in Stunden (HTTPERR, IIS, Application).

.PARAMETER MaxEvents
    Maximale Anzahl Events pro Abfrage.

.PARAMETER ReportPath
    Zielordner fuer den Report.

.PARAMETER SkipRemoteCheck
    Nur lokale Checks, kein WinRM.

.PARAMETER ImportOnly
    Nur Funktionen laden, kein Scan.

.EXAMPLE
    .\Find-CBTExposure.ps1
    .\Find-CBTExposure.ps1 -TargetScope AllServers
    .\Find-CBTExposure.ps1 -SkipRemoteCheck
    . .\Find-CBTExposure.ps1 -ImportOnly

.NOTES
    Version  : 1.0
    Kontext  : HTTP.sys CBT Enforcement ab Windows Update 2026.01B
    Referenz : HKLM\System\CurrentControlSet\Services\Http\Parameters\DefaultAuthHardeningLevel
    Symptom  : STATUS_BAD_BINDINGS / HTTP 401 Unauthorized bei Kerberos ueber HTTPS
    Ursache  : HTTP.sys haengt ab 2026.01B Channel Binding Tokens an den SSPI-Accept-Pfad.
               Clients ohne CBT-Hash im AP-REQ werden abgelehnt.
    Betrifft : Server hinter TLS-terminierenden Proxies (Kemp, NetScaler, F5, Sophos WAF)
#>

[CmdletBinding()]
param(
    [ValidateSet('DiscoveredOnly','AllServers','Full')]
    [string]$TargetScope = 'DiscoveredOnly',
    [int]$Hours = 24,
    [int]$MaxEvents = 500,
    [string]$ReportPath = 'C:\Temp',
    [switch]$SkipRemoteCheck,
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
$reportDir = Join-Path $ReportPath "CBT_${domainShort}_${ts}"

#region ============ HELPERS ============

function SafeCount { param($C) if ($null -eq $C) {0} elseif ($C -is [array]) {$C.Length} else {1} }

function Write-Status {
    param([string]$Label, [string]$Value, [string]$Color = 'White')
    Write-Host "  $($Label.PadRight(30)) $Value" -ForegroundColor $Color
}

function Format-EventCount {
    param([int]$Count, [int]$Max)
    if ($Count -ge $Max) { "$Count+ (MaxEvents erreicht)" } else { "$Count" }
}

function Get-HardeningLabel {
    param($Value)
    if ($null -eq $Value) { return 'Nicht gesetzt (folgt OS-Default)' }
    switch ([int]$Value) {
        0 { 'Legacy (vor 2026.01B)' }
        1 { 'Medium (2026.01B Default)' }
        2 { 'Strict' }
        default { "Unbekannt ($Value)" }
    }
}

function Get-HardeningBewertung {
    param($Value, [bool]$HasProxy, [bool]$HasWindowsAuth)
    if ($null -eq $Value -or [int]$Value -eq 0) {
        if ($HasProxy) { return 'Information — Legacy-Modus oder Workaround aktiv. Server hinter Proxy ist geschuetzt.' }
        return 'Information — Legacy-Modus. Kein CBT-Risiko.'
    }
    if ([int]$Value -eq 1) {
        if ($HasProxy) { return 'Warnung — Medium-Modus hinter TLS-Proxy. Clients ohne CBT-Hash erhalten 401.' }
        if ($HasWindowsAuth) { return 'Warnung — Medium-Modus mit Windows Auth. Pruefen ob Clients CBT unterstuetzen.' }
        return 'Information — Medium-Modus, kein Proxy, kein Windows Auth erkannt.'
    }
    if ([int]$Value -eq 2) {
        return 'Fehler — Strict-Modus. Alle Clients ohne CBT werden abgelehnt.'
    }
    return 'Unbekannt'
}

#endregion

#region ============ DISCOVERY ============

function Get-TargetServers {
    <#
    .SYNOPSIS
        Findet Server die fuer CBT-Pruefung relevant sind.
        DiscoveredOnly: Nur Server mit IIS/Exchange/Citrix/ADFS/Web-Rollen (~20-50 statt 5000).
        AllServers: Alle Server-OS Objekte.
        Full: Alle Computer inkl. Workstations.
    #>
    [CmdletBinding()]
    param([string]$TargetScope)

    Write-Host "`n=== SERVER DISCOVERY ($TargetScope) ===" -ForegroundColor Cyan

    $servers = @()

    if ($TargetScope -eq 'DiscoveredOnly') {
        # Phase 1: Rollen-basierte Erkennung — nur Server die HTTP.sys/IIS/Kerberos-Auth verwenden
        $discovered = @{}

        # Domain Controllers (immer relevant — haben IIS fuer CertSrv, ADWS, etc.)
        try {
            $dcs = @(Get-ADDomainController -Filter * -EA Stop)
            foreach ($dc in $dcs) {
                $key = $dc.HostName.ToLower()
                if (-not $discovered.ContainsKey($key)) {
                    $discovered[$key] = [PSCustomObject]@{ DNSHostName=$dc.HostName; Name=$dc.Name; Role='DC' }
                }
            }
            Write-Status "Domain Controller" "$(SafeCount $dcs)"
        } catch { Write-Host "  DC-Abfrage fehlgeschlagen: $_" -ForegroundColor DarkGray }

        # Exchange Server (ServiceConnectionPoint)
        try {
            $exchSCPs = @(Get-ADObject -Filter "objectClass -eq 'serviceConnectionPoint' -and Name -like '*Exchange*'" -Properties keywords, serviceBindingInformation -EA SilentlyContinue |
                Where-Object { $_.keywords -match '77378F46-2C66-4aa9-A6A6-3E7A48B19596' })
            foreach ($scp in $exchSCPs) {
                $uri = $scp.serviceBindingInformation | Select-Object -First 1
                if ($uri -match 'https?://([^/]+)') {
                    $fqdn = $Matches[1].ToLower()
                    if (-not $discovered.ContainsKey($fqdn)) {
                        $comp = try { Get-ADComputer -Filter "DNSHostName -eq '$fqdn'" -Properties DNSHostName -EA Stop | Select-Object -First 1 } catch { $null }
                        $discovered[$fqdn] = [PSCustomObject]@{ DNSHostName=$fqdn; Name=($fqdn -split '\.')[0]; Role='Exchange' }
                    }
                }
            }
            Write-Status "Exchange Server" "$(@($discovered.Values | Where-Object { $_.Role -eq 'Exchange' }).Count)"
        } catch {}

        # Citrix (DDC, StoreFront, NetScaler — gleiche Patterns wie Discover-RC4Environment)
        $citrixPatterns = @('*citrix*','*ddc*','*storefront*','*sfr*','*vda*','*netscaler*','*adc*','*xen*')
        $citrixCount = 0
        foreach ($pattern in $citrixPatterns) {
            try {
                $found = @(Get-ADComputer -Filter "Name -like '$pattern'" -Properties DNSHostName, OperatingSystem -EA SilentlyContinue |
                    Where-Object { $_.OperatingSystem -like '*Server*' -and $_.Enabled -ne $false })
                foreach ($f in $found) {
                    $key = $f.DNSHostName.ToLower()
                    if (-not $discovered.ContainsKey($key)) {
                        $discovered[$key] = [PSCustomObject]@{ DNSHostName=$f.DNSHostName; Name=$f.Name; Role='Citrix' }
                        $citrixCount++
                    }
                }
            } catch {}
        }
        if ($citrixCount -gt 0) { Write-Status "Citrix Server" "$citrixCount" }

        # ADFS
        try {
            $adfs = @(Get-ADObject -Filter "objectClass -eq 'serviceConnectionPoint' -and Name -eq 'ADFS'" -EA SilentlyContinue)
            foreach ($a in $adfs) {
                $parent = try { Get-ADComputer -Identity ($a.DistinguishedName -replace '^CN=[^,]+,','') -Properties DNSHostName -EA Stop } catch { $null }
                if ($parent -and $parent.DNSHostName) {
                    $key = $parent.DNSHostName.ToLower()
                    if (-not $discovered.ContainsKey($key)) {
                        $discovered[$key] = [PSCustomObject]@{ DNSHostName=$parent.DNSHostName; Name=$parent.Name; Role='ADFS' }
                    }
                }
            }
            $adfsCount = @($discovered.Values | Where-Object { $_.Role -eq 'ADFS' }).Count
            if ($adfsCount -gt 0) { Write-Status "ADFS Server" "$adfsCount" }
        } catch {}

        # Web-Server (Name-Patterns die auf IIS/Web hindeuten)
        $webPatterns = @('*web*','*iis*','*www*','*app*','*portal*','*intranet*','*sharepoint*','*sps*','*owa*','*wac*','*oos*')
        $webCount = 0
        foreach ($pattern in $webPatterns) {
            try {
                $found = @(Get-ADComputer -Filter "Name -like '$pattern'" -Properties DNSHostName, OperatingSystem -EA SilentlyContinue |
                    Where-Object { $_.OperatingSystem -like '*Server*' -and $_.Enabled -ne $false })
                foreach ($f in $found) {
                    $key = $f.DNSHostName.ToLower()
                    if (-not $discovered.ContainsKey($key)) {
                        $discovered[$key] = [PSCustomObject]@{ DNSHostName=$f.DNSHostName; Name=$f.Name; Role='Web/App' }
                        $webCount++
                    }
                }
            } catch {}
        }
        if ($webCount -gt 0) { Write-Status "Web/App Server" "$webCount" }

        # Constrained Delegation Targets (diese machen HTTP-basierte Delegation)
        try {
            $kcd = @(Get-ADComputer -Filter 'msDS-AllowedToDelegateTo -like "*"' -Properties DNSHostName, 'msDS-AllowedToDelegateTo' -EA SilentlyContinue |
                Where-Object { $_.Enabled -ne $false })
            foreach ($k in $kcd) {
                $key = $k.DNSHostName.ToLower()
                if (-not $discovered.ContainsKey($key)) {
                    $discovered[$key] = [PSCustomObject]@{ DNSHostName=$k.DNSHostName; Name=$k.Name; Role='KCD-Source' }
                }
                # Auch die Ziel-Server hinzufuegen
                foreach ($target in $k.'msDS-AllowedToDelegateTo') {
                    if ($target -match 'http/([^:]+)') {
                        $tFqdn = $Matches[1].ToLower()
                        if (-not $discovered.ContainsKey($tFqdn)) {
                            $comp = try { Get-ADComputer -Filter "DNSHostName -eq '$tFqdn'" -Properties DNSHostName -EA Stop | Select-Object -First 1 } catch { $null }
                            if ($comp) {
                                $discovered[$tFqdn] = [PSCustomObject]@{ DNSHostName=$tFqdn; Name=($tFqdn -split '\.')[0]; Role='KCD-Target' }
                            }
                        }
                    }
                }
            }
            $kcdCount = @($discovered.Values | Where-Object { $_.Role -match 'KCD' }).Count
            if ($kcdCount -gt 0) { Write-Status "KCD Source/Target" "$kcdCount" }
        } catch {}

        $servers = @($discovered.Values)
        Write-Status "Gesamt (DiscoveredOnly)" "$(SafeCount $servers)" 'Cyan'

        # Show role breakdown
        $servers | Group-Object Role | Sort-Object Count -Descending | ForEach-Object {
            Write-Host "    $($_.Name.PadRight(20)) $($_.Count)" -ForegroundColor DarkGray
        }
    }
    else {
        # AllServers or Full
        try {
            $ldapFilter = if ($TargetScope -eq 'AllServers') { 'OperatingSystem -like "*Server*"' } else { 'OperatingSystem -like "*"' }
            $raw = @(Get-ADComputer -Filter $ldapFilter -Properties OperatingSystem, DNSHostName -EA Stop |
                Where-Object { $_.Enabled -ne $false })
            $servers = @($raw | ForEach-Object {
                [PSCustomObject]@{ DNSHostName=$_.DNSHostName; Name=$_.Name; Role=$_.OperatingSystem }
            })
            Write-Status "Server gefunden" "$(SafeCount $servers) ($TargetScope)"
        }
        catch {
            Write-Host "  AD-Abfrage fehlgeschlagen: $_" -ForegroundColor Red
        }
    }

    return $servers
}

function Get-ProxyIndicators {
    <#
    .SYNOPSIS
        Erkennt TLS-terminierende Proxies in der Domaene (Kemp, NetScaler, F5, Sophos, HAProxy).
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n=== PROXY / LOAD BALANCER ERKENNUNG ===" -ForegroundColor Cyan

    $proxies = @()

    # Service Accounts die auf Proxy/LB hindeuten
    $proxyPatterns = @('*kemp*','*netscaler*','*citrixadc*','*f5*','*bigip*','*sophos*','*haproxy*','*nginx*','*loadbal*','*reverseprox*','*waf*')
    foreach ($pattern in $proxyPatterns) {
        try {
            $found = @(Get-ADComputer -Filter "Name -like '$pattern'" -Properties DNSHostName -EA SilentlyContinue)
            $found += @(Get-ADServiceAccount -Filter "Name -like '$pattern'" -EA SilentlyContinue)
            foreach ($f in $found) {
                $proxies += [PSCustomObject]@{
                    Name = $f.Name
                    Type = 'AD-Objekt'
                    Pattern = $pattern.Trim('*')
                    DNSHostName = if ($f.DNSHostName) { $f.DNSHostName } else { $f.Name }
                }
            }
        } catch {}
    }

    # DNS-Eintraege die auf externe VIPs hindeuten
    try {
        $cnames = @(Get-DnsServerResourceRecord -ZoneName $domainFQDN -RRType CNAME -EA SilentlyContinue |
            Where-Object { $_.RecordData.HostNameAlias -match 'kemp|netscaler|f5|sophos|adc|waf|lb' })
        foreach ($c in $cnames) {
            $proxies += [PSCustomObject]@{
                Name = $c.HostName
                Type = 'DNS CNAME'
                Pattern = $c.RecordData.HostNameAlias
                DNSHostName = "$($c.HostName).$domainFQDN"
            }
        }
    } catch {}

    Write-Status "Proxy/LB Indikatoren" "$(SafeCount $proxies)" $(if ((SafeCount $proxies) -gt 0) {'Yellow'} else {'Green'})
    foreach ($p in $proxies) {
        Write-Host "    $($p.Name) ($($p.Type): $($p.Pattern))" -ForegroundColor DarkGray
    }

    return $proxies
}

function Get-CBTStatus {
    <#
    .SYNOPSIS
        Prueft DefaultAuthHardeningLevel, IIS Windows Auth, WinRM HTTPS, HTTP.sys Reservierungen
        und Patch-Status per WinRM auf einem einzelnen Server.
    #>
    [CmdletBinding()]
    param([string]$ComputerName)

    $result = [PSCustomObject]@{
        Name                = $ComputerName
        Online              = $false
        HardeningLevel      = $null
        HardeningLabel      = ''
        Has2026_01B         = $null
        IISWindowsAuth      = @()
        IISSiteCount        = 0
        WinRMHttps          = $false
        HttpSysUrls         = 0
        ThirdPartyHttp      = @()
        Bewertung           = ''
    }

    try {
        $sb = {
            $out = @{}

            # 1. Registry: DefaultAuthHardeningLevel
            try {
                $reg = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Http\Parameters' -Name 'DefaultAuthHardeningLevel' -EA SilentlyContinue
                $out['HardeningLevel'] = if ($reg) { $reg.DefaultAuthHardeningLevel } else { $null }
            } catch { $out['HardeningLevel'] = $null }

            # 2. Patch-Status: 2026.01B oder neuer
            try {
                $patches = @(Get-HotFix -EA SilentlyContinue | Where-Object { $_.InstalledOn -ge [datetime]'2026-01-13' })
                $out['Has2026_01B'] = $patches.Count -gt 0
            } catch { $out['Has2026_01B'] = $null }

            # 3. IIS Windows Authentication
            $out['IISWindowsAuth'] = @()
            $out['IISSiteCount'] = 0
            try {
                Import-Module WebAdministration -EA Stop
                $sites = @(Get-Website -EA Stop)
                $out['IISSiteCount'] = $sites.Count
                foreach ($site in $sites) {
                    try {
                        $winAuth = Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name 'enabled' -PSPath "IIS:\Sites\$($site.Name)" -EA Stop
                        if ($winAuth.Value -eq $true) {
                            $out['IISWindowsAuth'] += "$($site.Name)|$($site.Bindings.Collection.bindingInformation -join ',')"
                        }
                    } catch {}
                }
            } catch {}

            # 4. WinRM HTTPS Listener
            try {
                $listeners = @(Get-ChildItem WSMan:\localhost\Listener -EA Stop | Where-Object { $_.Keys -contains 'Transport=HTTPS' })
                $out['WinRMHttps'] = $listeners.Count -gt 0
            } catch { $out['WinRMHttps'] = $false }

            # 5. HTTP.sys URL-Reservierungen (Drittanbieter)
            try {
                $urlacl = netsh http show urlacl 2>$null
                $urls = @($urlacl | Select-String 'https://' | Where-Object { $_ -notmatch 'wsman|WinRM|SSDP|UPnP|spn' })
                $out['HttpSysUrls'] = $urls.Count

                # Drittanbieter erkennen
                $thirdParty = @()
                $services = Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object {
                    $_.PathName -match 'httpd|apache|nginx|tomcat|jenkins|grafana|prometheus' -and $_.State -eq 'Running'
                }
                foreach ($svc in $services) {
                    $thirdParty += "$($svc.Name) ($($svc.PathName.Substring(0, [Math]::Min(60, $svc.PathName.Length))))"
                }
                $out['ThirdPartyHttp'] = $thirdParty
            } catch { $out['HttpSysUrls'] = 0; $out['ThirdPartyHttp'] = @() }

            return $out
        }

        $r = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sb -EA Stop
        $result.Online = $true
        $result.HardeningLevel = $r.HardeningLevel
        $result.HardeningLabel = Get-HardeningLabel $r.HardeningLevel
        $result.Has2026_01B = $r.Has2026_01B
        $result.IISWindowsAuth = $r.IISWindowsAuth
        $result.IISSiteCount = $r.IISSiteCount
        $result.WinRMHttps = $r.WinRMHttps
        $result.HttpSysUrls = $r.HttpSysUrls
        $result.ThirdPartyHttp = $r.ThirdPartyHttp
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Zugriff verweigert') {
            $result.Bewertung = 'Zugriff verweigert — manuell pruefen'
        }
        elseif ($_.Exception.Message -match 'cannot connect|nicht erreichbar|WinRM') {
            $result.Bewertung = 'Nicht erreichbar (WinRM)'
        }
        else {
            $result.Bewertung = "Fehler: $($_.Exception.Message.Substring(0, [Math]::Min(80, $_.Exception.Message.Length)))"
        }
    }

    return $result
}

function Get-LocalCBTStatus {
    <#
    .SYNOPSIS
        Prueft den lokalen Server (ohne WinRM).
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n=== LOKALER CBT-STATUS ===" -ForegroundColor Cyan

    $result = [PSCustomObject]@{
        Name           = $env:COMPUTERNAME
        HardeningLevel = $null
        HardeningLabel = ''
        Has2026_01B    = $null
    }

    # Registry
    try {
        $reg = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Http\Parameters' -Name 'DefaultAuthHardeningLevel' -EA SilentlyContinue
        $result.HardeningLevel = if ($reg) { $reg.DefaultAuthHardeningLevel } else { $null }
        $result.HardeningLabel = Get-HardeningLabel $result.HardeningLevel
    } catch {}

    # Patch
    try {
        $patches = @(Get-HotFix -EA SilentlyContinue | Where-Object { $_.InstalledOn -ge [datetime]'2026-01-13' })
        $result.Has2026_01B = $patches.Count -gt 0
    } catch {}

    Write-Status "DefaultAuthHardeningLevel" $result.HardeningLabel $(
        switch ($result.HardeningLevel) { 0 {'Green'} 1 {'Yellow'} 2 {'Red'} default {'DarkGray'} }
    )
    Write-Status "2026.01B oder neuer" $(if ($result.Has2026_01B) {'Ja'} elseif ($null -eq $result.Has2026_01B) {'Unbekannt'} else {'Nein'}) $(
        if ($result.Has2026_01B) {'Yellow'} else {'Green'}
    )

    return $result
}

function Get-CBTEventCorrelation {
    <#
    .SYNOPSIS
        6 FilterXML-Checks fuer CBT-Probleme. Gleiche Methodik wie Prove-RC4Usage.ps1.
        Korreliert Kerberos-Ticket-Ausstellung (4769) mit Auth-Fehler (4625) —
        wenn das Ticket gueltig ist aber die Authentifizierung trotzdem fehlschlaegt,
        ist CBT die wahrscheinliche Ursache.
    #>
    [CmdletBinding()]
    param([int]$MsBack, [int]$Max = 500)

    Write-Host "`n=== CBT EVENT-KORRELATION (6 Checks) ===" -ForegroundColor Yellow

    $allEvents = @()
    $summary = @{}

    # ── Check 1: Event 4625 SubStatus 0xC000035B (STATUS_BAD_BINDINGS) ──
    # Das ist der direkte Beweis. Wenn dieses Event existiert, ist CBT die Ursache.
    Write-Host "`n  [1/6] Event 4625 SubStatus 0xC000035B (STATUS_BAD_BINDINGS)" -ForegroundColor White
    $xml1 = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= $MsBack]]]
and *[EventData[Data[@Name='SubStatus']='0xc000035b']]
</Select></Query></QueryList>
"@
    try {
        $raw = @(Get-WinEvent -FilterXml $xml1 -MaxEvents $Max -EA Stop)
        $summary['4625_BAD_BINDINGS'] = $raw.Count
        Write-Status "    STATUS_BAD_BINDINGS" "$(Format-EventCount $raw.Count $Max)" $(if ($raw.Count -gt 0) {'Red'} else {'Green'})

        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $acct = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' } catch { '?' }
            $ws   = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text' } catch { '?' }
            $ip   = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text' } catch { '?' }
            $proc = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonProcessName' }).'#text' } catch { '?' }
            $allEvents += [PSCustomObject]@{
                Time=$evt.TimeCreated; Check='BAD_BINDINGS'; EventID=4625
                Account=$acct; Source=$ws; IP=$ip; Detail="SubStatus=0xC000035B LogonProcess=$proc"
            }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found|Es wurden keine') {
            Write-Host "    Fehler: $($_.Exception.Message)" -ForegroundColor DarkGray
        } else {
            $summary['4625_BAD_BINDINGS'] = 0
            Write-Status "    STATUS_BAD_BINDINGS" "0" 'Green'
        }
    }

    # ── Check 2: Event 4625 SubStatus 0xC0000388 (STATUS_DOWNGRADE_DETECTED) ──
    Write-Host "`n  [2/6] Event 4625 SubStatus 0xC0000388 (STATUS_DOWNGRADE_DETECTED)" -ForegroundColor White
    $xml2 = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= $MsBack]]]
and *[EventData[Data[@Name='SubStatus']='0xc0000388']]
</Select></Query></QueryList>
"@
    try {
        $raw = @(Get-WinEvent -FilterXml $xml2 -MaxEvents $Max -EA Stop)
        $summary['4625_DOWNGRADE'] = $raw.Count
        Write-Status "    DOWNGRADE_DETECTED" "$(Format-EventCount $raw.Count $Max)" $(if ($raw.Count -gt 0) {'Yellow'} else {'Green'})

        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $acct = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' } catch { '?' }
            $ip   = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text' } catch { '?' }
            $allEvents += [PSCustomObject]@{
                Time=$evt.TimeCreated; Check='DOWNGRADE'; EventID=4625
                Account=$acct; Source=''; IP=$ip; Detail="SubStatus=0xC0000388"
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            $summary['4625_DOWNGRADE'] = 0
            Write-Status "    DOWNGRADE_DETECTED" "0" 'Green'
        }
    }

    # ── Check 3: Event 4625 mit Negotiate/Kerberos (breiteres Netz) ──
    # Nicht-Passwort-Fehler bei Negotiate = entweder RC4 oder CBT
    Write-Host "`n  [3/6] Event 4625 Negotiate (nicht Passwort-Fehler)" -ForegroundColor White
    $xml3 = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= $MsBack]]]
and *[EventData[Data[@Name='AuthenticationPackageName']='Negotiate']]
</Select></Query></QueryList>
"@
    $negotiate401 = 0
    $negotiateNonPw = 0
    try {
        $raw = @(Get-WinEvent -FilterXml $xml3 -MaxEvents $Max -EA Stop)
        $negotiate401 = $raw.Count
        # Filtern: nur Fehler die NICHT Passwort-bezogen sind (0xC000006A = wrong pw, 0xC0000064 = user not found)
        foreach ($evt in $raw) {
            $x = [xml]$evt.ToXml()
            $sub = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'SubStatus' }).'#text' } catch { '' }
            if ($sub -notin @('0xc000006a','0xc0000064','0xc000006d','0xc0000071','0xc0000072','0xc0000234')) {
                $negotiateNonPw++
                $acct = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' } catch { '?' }
                $ip   = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text' } catch { '?' }
                $allEvents += [PSCustomObject]@{
                    Time=$evt.TimeCreated; Check='Negotiate_NonPW'; EventID=4625
                    Account=$acct; Source=''; IP=$ip; Detail="SubStatus=$sub AuthPkg=Negotiate"
                }
            }
        }
        $summary['4625_Negotiate'] = $negotiate401
        $summary['4625_Negotiate_NonPW'] = $negotiateNonPw
        Write-Status "    Negotiate gesamt" "$negotiate401"
        Write-Status "    davon nicht Passwort" "$negotiateNonPw" $(if ($negotiateNonPw -gt 0) {'Yellow'} else {'Green'})
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            $summary['4625_Negotiate'] = 0; $summary['4625_Negotiate_NonPW'] = 0
            Write-Status "    Negotiate" "0" 'Green'
        }
    }

    # ── Check 4: HttpService Events im System Log ──
    Write-Host "`n  [4/6] System Log HttpService (SSL/TLS-Fehler)" -ForegroundColor White
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-HttpService'
            StartTime = (Get-Date).AddMilliseconds(-$MsBack)
        } -MaxEvents $Max -EA SilentlyContinue)
        $summary['HttpService'] = $raw.Count
        Write-Status "    HttpService Events" "$(Format-EventCount $raw.Count $Max)" $(if ($raw.Count -gt 0) {'Yellow'} else {'Green'})
        foreach ($evt in $raw) {
            $allEvents += [PSCustomObject]@{
                Time=$evt.TimeCreated; Check='HttpService'; EventID=$evt.Id
                Account=''; Source=$evt.ProviderName; IP=''; Detail=$evt.Message.Substring(0, [Math]::Min(120, $evt.Message.Length))
            }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found|Es wurden keine') {
            $summary['HttpService'] = 0
            Write-Status "    HttpService Events" "0" 'Green'
        }
    }

    # ── Check 5: HTTPERR Logdateien ──
    Write-Host "`n  [5/6] HTTPERR Logdateien (BAD_BINDINGS, Negotiate+401)" -ForegroundColor White
    $httperrPath = "${env:SystemRoot}\System32\LogFiles\HTTPERR"
    $summary['HTTPERR_BAD_BINDINGS'] = 0
    $summary['HTTPERR_Negotiate401'] = 0
    if (Test-Path $httperrPath) {
        $cutoff = (Get-Date).AddHours(-($MsBack / 3600000))
        $logFiles = @(Get-ChildItem $httperrPath -Filter 'httperr*.log' -EA SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 10)

        foreach ($lf in $logFiles) {
            $lines = @(Get-Content $lf.FullName -Tail 1000 -EA SilentlyContinue)

            $bb = @($lines | Select-String 'BAD_BINDINGS' -SimpleMatch)
            $summary['HTTPERR_BAD_BINDINGS'] += $bb.Count
            foreach ($match in $bb) {
                # HTTPERR format: date time c-ip c-port s-ip s-port cs-version cs-method cs-uri ... reason
                $parts = ($match.Line -split '\s+')
                $allEvents += [PSCustomObject]@{
                    Time=if($parts.Count -ge 2){"$($parts[0]) $($parts[1])"}else{''};
                    Check='HTTPERR_BAD_BINDINGS'; EventID=0
                    Account=''; Source=$lf.Name
                    IP=if($parts.Count -ge 3){$parts[2]}else{''}
                    Detail='STATUS_BAD_BINDINGS in HTTPERR'
                }
            }

            $neg = @($lines | Select-String 'Negotiate' | Select-String '401')
            $summary['HTTPERR_Negotiate401'] += $neg.Count
        }
        Write-Status "    BAD_BINDINGS" "$($summary['HTTPERR_BAD_BINDINGS'])" $(if ($summary['HTTPERR_BAD_BINDINGS'] -gt 0) {'Red'} else {'Green'})
        Write-Status "    Negotiate+401" "$($summary['HTTPERR_Negotiate401'])" $(if ($summary['HTTPERR_Negotiate401'] -gt 0) {'Yellow'} else {'Green'})
    }
    else {
        Write-Host "    HTTPERR-Pfad nicht gefunden" -ForegroundColor DarkGray
    }

    # ── Check 6: Korrelation 4769 (Ticket OK) + 4625 (Auth Fehler) = CBT ──
    # Wenn der KDC ein gueltiges AES-Ticket ausstellt (4769 Success)
    # und innerhalb von 5 Sekunden ein 4625 fuer denselben Account kommt,
    # ist das Ticket nicht das Problem — CBT ist die wahrscheinliche Ursache.
    Write-Host "`n  [6/6] Korrelation: 4769-Success + 4625-Failure (gleicher Account, <5s)" -ForegroundColor White

    $correlated = @()
    try {
        # Letzte erfolgreiche Service Tickets (nur AES = 0x11/0x12)
        $xml4769 = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) &lt;= $MsBack]]]
and *[EventData[Data[@Name='Status']='0x0']]
and *[EventData[(Data[@Name='TicketEncryptionType']='0x12') or (Data[@Name='TicketEncryptionType']='0x11')]]
</Select></Query></QueryList>
"@
        $tickets = @(Get-WinEvent -FilterXml $xml4769 -MaxEvents ($Max * 2) -EA SilentlyContinue)

        # Alle 4625 Negotiate-Fehler (bereits aus Check 3)
        $failures = @($allEvents | Where-Object { $_.EventID -eq 4625 -and $_.Check -match 'Negotiate|BAD_BINDINGS' })

        if ($tickets.Count -gt 0 -and $failures.Count -gt 0) {
            # Index: Account → Ticket-Zeiten
            $ticketIndex = @{}
            foreach ($t in $tickets) {
                $x = [xml]$t.ToXml()
                $acct = try { ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' } catch { '' }
                if ($acct -and $acct -ne '$') {
                    $key = $acct.ToLower()
                    if (-not $ticketIndex.ContainsKey($key)) { $ticketIndex[$key] = @() }
                    $ticketIndex[$key] += $t.TimeCreated
                }
            }

            # Korrelieren: 4625 innerhalb von 5s nach einem 4769 fuer denselben Account
            foreach ($f in $failures) {
                $acctKey = $f.Account.ToLower()
                if ($ticketIndex.ContainsKey($acctKey)) {
                    foreach ($tTime in $ticketIndex[$acctKey]) {
                        $delta = ($f.Time - $tTime).TotalSeconds
                        if ($delta -ge 0 -and $delta -le 5) {
                            $correlated += [PSCustomObject]@{
                                Time = $f.Time
                                Account = $f.Account
                                IP = $f.IP
                                TicketTime = $tTime
                                DeltaSeconds = [Math]::Round($delta, 1)
                                Check = $f.Check
                                Bewertung = 'Ticket gueltig (AES), Auth fehlgeschlagen → CBT wahrscheinlich'
                            }
                            break
                        }
                    }
                }
            }
        }

        $summary['Correlated'] = $correlated.Count
        Write-Status "    Korrelierte Events" "$($correlated.Count)" $(if ($correlated.Count -gt 0) {'Red'} else {'Green'})

        if ($correlated.Count -gt 0) {
            Write-Host ""
            Write-Host "    Korrelierte Accounts (Ticket OK → Auth Fehler):" -ForegroundColor Red
            $correlated | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
                Write-Host "      $($_.Name.PadRight(25)) $($_.Count)x (Delta: $( ($_.Group | Measure-Object -Property DeltaSeconds -Average).Average )s)" -ForegroundColor Red
            }
        }
    } catch {
        $summary['Correlated'] = 0
        Write-Host "    Korrelation nicht moeglich: $_" -ForegroundColor DarkGray
    }

    # ── Zusammenfassung ──
    Write-Host "`n  --- ZUSAMMENFASSUNG EVENT-KORRELATION ---" -ForegroundColor Cyan
    $evidence = ($summary['4625_BAD_BINDINGS'] -gt 0) -or ($summary['HTTPERR_BAD_BINDINGS'] -gt 0)
    $suspicious = ($summary['4625_Negotiate_NonPW'] -gt 0) -or ($summary['Correlated'] -gt 0)

    if ($evidence) {
        Write-Host "  ERGEBNIS: CBT-Problem NACHGEWIESEN (STATUS_BAD_BINDINGS in Events)" -ForegroundColor Red
        Write-Host "  Mitigation: DefaultAuthHardeningLevel = 0 auf betroffenen Servern" -ForegroundColor Red
    }
    elseif ($suspicious) {
        Write-Host "  ERGEBNIS: CBT-Problem MOEGLICH (Negotiate-Fehler ohne Passwort-Ursache)" -ForegroundColor Yellow
        Write-Host "  Empfehlung: HTTPERR-Logs und Network-Trace auf betroffenen Servern pruefen" -ForegroundColor Yellow
    }
    else {
        Write-Host "  ERGEBNIS: Keine CBT-Indikatoren erkannt" -ForegroundColor Green
    }

    return @{
        Events = $allEvents
        Correlated = $correlated
        Summary = $summary
        Evidence = $evidence
        Suspicious = $suspicious
    }
}

#endregion

#region ============ CROSS-CHECK ============

function Write-CBTBewertung {
    [CmdletBinding()]
    param(
        [array]$Results,
        [array]$Proxies,
        $LocalStatus,
        $EventResult
    )

    Write-Host "`n=== CBT BEWERTUNG ===" -ForegroundColor Cyan

    $findings = @()
    $proxyNames = @($Proxies | ForEach-Object { $_.Name.ToLower() })

    # Per-Server Bewertung
    foreach ($r in $Results) {
        $behindProxy = $false
        # Heuristik: Exchange, StoreFront, Web-Apps sind typischerweise hinter Proxies
        if ($r.IISWindowsAuth.Count -gt 0) {
            $siteNames = ($r.IISWindowsAuth | ForEach-Object { ($_ -split '\|')[0] }) -join ','
            if ($siteNames -match 'Exchange|Default Web Site|StoreFront') { $behindProxy = $true }
        }

        $r.Bewertung = Get-HardeningBewertung -Value $r.HardeningLevel -HasProxy $behindProxy -HasWindowsAuth ($r.IISWindowsAuth.Count -gt 0)
    }

    # Aggregierte Findings
    $patched = @($Results | Where-Object { $_.Has2026_01B -eq $true })
    $medium = @($Results | Where-Object { ($_.HardeningLevel -eq 1) -or ($null -eq $_.HardeningLevel -and $_.Has2026_01B -eq $true) })
    $withIIS = @($Results | Where-Object { $_.IISWindowsAuth.Count -gt 0 })
    $withThirdParty = @($Results | Where-Object { $_.ThirdPartyHttp.Count -gt 0 })

    # Finding 1: Patch-Stand
    $findings += [PSCustomObject]@{
        Nr=1; Typ=if($patched.Count -gt 0){'Warnung'}else{'Information'}
        Bereich='2026.01B Patch-Status'
        Befund="$(SafeCount $patched) von $(SafeCount $Results) Server haben 2026.01B oder neuer."
        Bewertung=if($patched.Count -gt 0){"$($patched.Count) Server mit neuem CBT-Verhalten. DefaultAuthHardeningLevel pruefen."}else{"Noch kein Server gepatcht. CBT-Verhalten ist noch nicht aktiv."}
        Bedingung="Nach Installation von 2026.01B aendert sich das HTTP.sys-Verhalten automatisch."
    }

    # Finding 2: Server mit Medium/Strict hinter Proxy
    $atRisk = @($withIIS | Where-Object {
        ($_.HardeningLevel -eq 1 -or $_.HardeningLevel -eq 2 -or ($null -eq $_.HardeningLevel -and $_.Has2026_01B -eq $true))
    })
    if ((SafeCount $atRisk) -gt 0) {
        $names = ($atRisk | ForEach-Object { $_.Name }) -join ', '
        $findings += [PSCustomObject]@{
            Nr=2; Typ='Warnung'
            Bereich='IIS Windows Auth + CBT Medium/Strict'
            Befund="$(SafeCount $atRisk) Server mit IIS Windows Authentication und aktivem CBT: $names"
            Bewertung="Server mit Windows Integrated Auth und CBT Medium/Strict lehnen Clients ab die kein CBT-Hash im Kerberos AP-REQ mitschicken. Betrifft alle Zugriffe ueber TLS-terminierende Proxies."
            Bedingung="Workaround: DefaultAuthHardeningLevel = 0 setzen bis Microsoft-Fix verfuegbar."
        }
    }

    # Finding 3: Drittanbieter HTTP.sys
    if ((SafeCount $withThirdParty) -gt 0) {
        $tp = ($withThirdParty | ForEach-Object { "$($_.Name): $($_.ThirdPartyHttp -join ', ')" }) -join "`n"
        $findings += [PSCustomObject]@{
            Nr=3; Typ='Warnung'
            Bereich='Drittanbieter-Applikationen mit HTTP.sys'
            Befund="$(SafeCount $withThirdParty) Server mit Drittanbieter-HTTP-Diensten (Apache, Tomcat, Jenkins, etc.)."
            Bewertung="Drittanbieter-Apps die HTTP.sys mit Negotiate/Kerberos verwenden sind genauso betroffen wie IIS. Der MS-Kontakt-Case beschreibt genau dieses Szenario (Apache auf Windows mit SSPI)."
            Bedingung="Pruefen ob die App SSPI/Negotiate verwendet. Wenn ja: DefaultAuthHardeningLevel = 0."
        }
    }

    # Finding 4: Proxy-Indikatoren
    if ((SafeCount $Proxies) -gt 0) {
        $pNames = ($Proxies | ForEach-Object { "$($_.Name) ($($_.Type))" }) -join ', '
        $findings += [PSCustomObject]@{
            Nr=4; Typ='Information'
            Bereich='TLS-terminierende Proxies erkannt'
            Befund="$(SafeCount $Proxies) Proxy/LoadBalancer-Indikatoren: $pNames"
            Bewertung="TLS-Terminierung am Proxy fuehrt dazu dass der Backend-Server eine andere TLS-Session sieht als der Client. Das Channel Binding Hash stimmt dann nicht ueberein. Betrifft: SSL Offloading, SSL Bridging, Reverse Proxy mit eigener TLS-Terminierung."
            Bedingung="Nur relevant fuer Server die hinter diesen Proxies stehen UND CBT Medium oder Strict haben."
        }
    }

    # Finding 5: Event-Korrelation
    if ($EventResult) {
        $sum = $EventResult.Summary
        if ($EventResult.Evidence) {
            $bbCount = if ($sum['4625_BAD_BINDINGS']) { $sum['4625_BAD_BINDINGS'] } else { 0 }
            $heCount = if ($sum['HTTPERR_BAD_BINDINGS']) { $sum['HTTPERR_BAD_BINDINGS'] } else { 0 }
            $findings += [PSCustomObject]@{
                Nr=5; Typ='Fehler'
                Bereich='STATUS_BAD_BINDINGS nachgewiesen'
                Befund="$bbCount Event(s) 4625 mit SubStatus 0xC000035B, $heCount HTTPERR BAD_BINDINGS. CBT-Problem bestaetigt."
                Bewertung="Kerberos-Tickets werden gueltig ausgestellt aber von HTTP.sys wegen fehlendem Channel Binding Hash abgelehnt. Sofort DefaultAuthHardeningLevel = 0 setzen."
                Bedingung="Betrifft alle Clients die ueber TLS-terminierende Proxies zugreifen."
            }
        }
        elseif ($EventResult.Suspicious) {
            $corrCount = if ($sum['Correlated']) { $sum['Correlated'] } else { 0 }
            $negCount  = if ($sum['4625_Negotiate_NonPW']) { $sum['4625_Negotiate_NonPW'] } else { 0 }
            $findings += [PSCustomObject]@{
                Nr=5; Typ='Warnung'
                Bereich='CBT-Verdacht (Negotiate-Fehler ohne Passwort-Ursache)'
                Befund="$negCount Negotiate-Auth-Fehler ohne Passwort-Ursache, $corrCount korreliert mit gueltigem AES-Ticket (<5s Delta)."
                Bewertung="Kerberos-Ticket wurde gueltig ausgestellt, Authentifizierung ist trotzdem fehlgeschlagen. CBT ist die wahrscheinliche Ursache. HTTPERR-Logs und Network-Trace pruefen."
                Bedingung="DefaultAuthHardeningLevel pruefen. Wenn 1 oder 2: auf 0 setzen und erneut testen."
            }
        }
        elseif ($sum) {
            $findings += [PSCustomObject]@{
                Nr=5; Typ='Information'
                Bereich='Event-Korrelation'
                Befund="Keine CBT-Indikatoren in den Event-Logs. 0 STATUS_BAD_BINDINGS, 0 korrelierte Ticket/Auth-Fehler."
                Bewertung="Kein CBT-Problem erkannt. Die Umgebung ist aktuell nicht betroffen."
                Bedingung="Nach Installation von 2026.01B erneut pruefen."
            }
        }
    }

    # Output
    foreach ($f in $findings) {
        $color = switch ($f.Typ) { 'Fehler' {'Red'}; 'Warnung' {'Yellow'}; default {'Green'} }
        Write-Host ""
        Write-Host "  [$($f.Nr)] $($f.Typ): $($f.Bereich)" -ForegroundColor $color
        Write-Host "      $($f.Befund)" -ForegroundColor White
        Write-Host "      $($f.Bewertung)" -ForegroundColor DarkGray
    }

    Write-Host ""
    $fehler = @($findings | Where-Object { $_.Typ -eq 'Fehler' }).Count
    $warnung = @($findings | Where-Object { $_.Typ -eq 'Warnung' }).Count
    $info = @($findings | Where-Object { $_.Typ -eq 'Information' }).Count
    Write-Host "  Fehler: $fehler | Warnungen: $warnung | Information: $info" -ForegroundColor Cyan

    return $findings
}

#endregion

#region ============ EXPORT ============

function Export-CBTReport {
    [CmdletBinding()]
    param(
        [array]$Results,
        [array]$Proxies,
        [array]$Findings,
        [array]$Events,
        [array]$Correlated,
        [string]$Path
    )

    Write-Host "`n=== EXPORT ===" -ForegroundColor Cyan

    # CSV: Server-Ergebnisse
    $csvData = @($Results | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Online = $_.Online
            HardeningLevel = $_.HardeningLevel
            HardeningLabel = $_.HardeningLabel
            Has2026_01B = $_.Has2026_01B
            IISSites = $_.IISSiteCount
            IISWindowsAuth = ($_.IISWindowsAuth -join '; ')
            WinRMHttps = $_.WinRMHttps
            HttpSysUrls = $_.HttpSysUrls
            ThirdPartyHttp = ($_.ThirdPartyHttp -join '; ')
            Bewertung = $_.Bewertung
        }
    })
    $csvData | Export-Csv (Join-Path $Path 'CBT_Servers.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "  CSV: CBT_Servers.csv ($(SafeCount $csvData) Server)" -ForegroundColor Green

    # CSV: Proxies
    if ((SafeCount $Proxies) -gt 0) {
        $Proxies | Export-Csv (Join-Path $Path 'CBT_Proxies.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: CBT_Proxies.csv ($(SafeCount $Proxies))" -ForegroundColor Green
    }

    # CSV: Findings
    if ((SafeCount $Findings) -gt 0) {
        $Findings | Export-Csv (Join-Path $Path 'CBT_Findings.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: CBT_Findings.csv ($(SafeCount $Findings))" -ForegroundColor Green
    }

    # CSV: Events
    if ((SafeCount $Events) -gt 0) {
        $Events | Export-Csv (Join-Path $Path 'CBT_Events.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: CBT_Events.csv ($(SafeCount $Events))" -ForegroundColor Green
    }

    # CSV: Korrelierte Events (Ticket OK → Auth Fehler)
    if ((SafeCount $Correlated) -gt 0) {
        $Correlated | Export-Csv (Join-Path $Path 'CBT_Correlated.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: CBT_Correlated.csv ($(SafeCount $Correlated)) — Ticket OK, Auth fehlgeschlagen" -ForegroundColor Red
    }

    # Excel (optional)
    $hasExcel = $false
    try { Import-Module ImportExcel -EA Stop; $hasExcel = $true } catch {}

    if ($hasExcel) {
        $xlPath = Join-Path $Path "CBT_${domainShort}_Report.xlsx"

        $ctLevel = @(
            (New-ConditionalText 'Legacy'  -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
            (New-ConditionalText 'Medium'  -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            (New-ConditionalText 'Strict'  -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
        )

        $csvData | Export-Excel -Path $xlPath -WorksheetName 'Server' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $ctLevel

        if ((SafeCount $Findings) -gt 0) {
            $ctFindings = @(
                (New-ConditionalText 'Fehler'      -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
                (New-ConditionalText 'Warnung'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
                (New-ConditionalText 'Information' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
            )
            $Findings | Export-Excel -Path $xlPath -WorksheetName 'Findings' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText $ctFindings
        }

        if ((SafeCount $Correlated) -gt 0) {
            $Correlated | Export-Excel -Path $xlPath -WorksheetName 'Korrelation' -AutoSize -FreezeTopRow -BoldTopRow -Append -ConditionalText @(
                (New-ConditionalText 'BAD_BINDINGS'  -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
                (New-ConditionalText 'CBT'           -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            )
        }

        Write-Host "  Excel: $xlPath" -ForegroundColor Green
    }

    # ZIP
    $zipPath = "${Path}.zip"
    try {
        Compress-Archive -Path "$Path\*" -DestinationPath $zipPath -Force -EA Stop
        Write-Host "  ZIP: $zipPath" -ForegroundColor Green
    } catch {
        Write-Host "  ZIP fehlgeschlagen: $_" -ForegroundColor DarkGray
    }
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
    Write-Host "  Verfuegbare Funktionen:" -ForegroundColor DarkGray
    Write-Host "    Get-TargetServers       Get-ProxyIndicators" -ForegroundColor DarkGray
    Write-Host "    Get-CBTStatus           Get-LocalCBTStatus" -ForegroundColor DarkGray
    Write-Host "    Get-CBTEventCorrelation       Write-CBTBewertung" -ForegroundColor DarkGray
    Write-Host "    Export-CBTReport        Get-HardeningLabel" -ForegroundColor DarkGray
}
elseif (-not $script:_IsDotSourced) {

if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
$msBack = $Hours * 3600 * 1000

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  CBT Exposure Analysis v1.0" -ForegroundColor Cyan
Write-Host "  Domaene: $domainFQDN ($domainShort)" -ForegroundColor Cyan
Write-Host "  Scope: $TargetScope | Zeitraum: $Hours Stunden" -ForegroundColor Cyan
Write-Host "  Report: $reportDir" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# Phase 1: Discovery
$localStatus = Get-LocalCBTStatus
$proxies = Get-ProxyIndicators
$servers = Get-TargetServers -TargetScope $TargetScope

# Phase 2: Remote Check
$results = @()
if (-not $SkipRemoteCheck -and (SafeCount $servers) -gt 0) {
    Write-Host "`n=== REMOTE CBT-CHECK ($(SafeCount $servers) Server) ===" -ForegroundColor Cyan

    $i = 0
    foreach ($srv in $servers) {
        $i++
        $name = if ($srv.DNSHostName) { $srv.DNSHostName } else { $srv.Name }
        Write-Progress -Activity "CBT-Check" -Status $name -PercentComplete (($i / $servers.Count) * 100)

        $r = Get-CBTStatus -ComputerName $name

        $statusColor = if (-not $r.Online) {'DarkGray'} elseif ($r.HardeningLevel -eq 2) {'Red'} elseif ($r.HardeningLevel -eq 1) {'Yellow'} else {'Green'}
        $authInfo = if ($r.IISWindowsAuth.Count -gt 0) { " IIS-WinAuth:$($r.IISWindowsAuth.Count)" } else { '' }
        $tpInfo = if ($r.ThirdPartyHttp.Count -gt 0) { " 3rdParty:$($r.ThirdPartyHttp.Count)" } else { '' }

        Write-Host "  $($name.PadRight(30)) $($r.HardeningLabel.PadRight(35))$authInfo$tpInfo" -ForegroundColor $statusColor
        $results += $r
    }
    Write-Progress -Activity "CBT-Check" -Completed
}
elseif ($SkipRemoteCheck) {
    Write-Host "`n  Remote-Check uebersprungen (-SkipRemoteCheck)" -ForegroundColor DarkGray
}

# Phase 3: Events (lokal)
$eventResult = Get-CBTEventCorrelation -MsBack $msBack -Max $MaxEvents
$events = $eventResult.Events
$correlated = $eventResult.Correlated

# Phase 4: Bewertung
$findings = Write-CBTBewertung -Results $results -Proxies $proxies -LocalStatus $localStatus -EventResult $eventResult

# Phase 5: Export
Export-CBTReport -Results $results -Proxies $proxies -Findings $findings -Events $events -Correlated $correlated -Path $reportDir

# Summary
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  CBT Exposure Analysis abgeschlossen." -ForegroundColor Cyan
Write-Host "  Report: $reportDir" -ForegroundColor White
Write-Host ""
Write-Host "  Workaround bei CBT-Problemen:" -ForegroundColor Yellow
Write-Host "  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Http\Parameters' ``" -ForegroundColor White
Write-Host "      -Name 'DefaultAuthHardeningLevel' -Value 0 -Type DWord" -ForegroundColor White
Write-Host "  # Neustart des HTTP-Dienstes oder Reboot erforderlich" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Referenzen:" -ForegroundColor DarkGray
Write-Host "  - Microsoft Case: STATUS_BAD_BINDINGS nach 2026.01B" -ForegroundColor DarkGray
Write-Host "  - HKLM\System\CurrentControlSet\Services\Http\Parameters\DefaultAuthHardeningLevel" -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

} # end elseif (-not $script:_IsDotSourced)

#endregion
