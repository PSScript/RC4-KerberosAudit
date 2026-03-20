#Requires -Version 5.1
<#
.SYNOPSIS
    Erkennt RC4-anfaellige Systeme (Citrix, Igel, VMware, Linux, Appliances)
    und korreliert Kerberos-Events mit Anmeldefehlern.

.DESCRIPTION
    Ergaenzung zu Check-Server2025Defaults und Prove-RC4Usage.
    Fokus auf heterogene Umgebungen: Thin Clients, Virtualisierung,
    Linux/Appliances und deren Kerberos-Interaktion mit dem DC.

    Phasen:
    1. AD-Discovery: Citrix, Igel, VMware, Non-Windows, Delegation-Accounts
    2. GPO: Kerberos Encryption Policy auf DCs
    3. Event-Korrelation: RC4-Tickets → Anmeldefehler → Lockouts (FilterXML)
    4. Report: Excel mit Highlighting, CSVs, ZIP, optionaler E-Mail

.PARAMETER Hours
    Event-Log Zeitraum in Stunden. Standard: 24

.PARAMETER MaxEvents
    Max Events pro Abfrage. Standard: 1000

.PARAMETER ReportPath
    Zielordner. Standard: C:\Temp

.PARAMETER SkipEvents
    Nur AD-Discovery, keine Event-Log-Analyse.

.PARAMETER SendMail
    E-Mail-Versand des ZIP-Reports.

.PARAMETER MailTo
    Empfaenger der E-Mail.

.PARAMETER MailFrom
    Absender der E-Mail.

.PARAMETER SmtpServer
    SMTP-Server fuer den E-Mail-Versand.

.PARAMETER ReassessFrom
    Pfad zu einem vorherigen Report-Ordner (z.B. C:\Temp\RC4_CONTOSO_20260319_162051).
    Laedt die CSVs und fuehrt nur Kreuzpruefung und Bewertung durch, ohne AD-Abfragen oder Event-Log-Analyse.

.EXAMPLE
    .\Discover-RC4Environment.ps1
    .\Discover-RC4Environment.ps1 -Hours 72 -MaxEvents 2000
    .\Discover-RC4Environment.ps1 -SkipEvents
    .\Discover-RC4Environment.ps1 -ReassessFrom 'C:\Temp\RC4_CONTOSO_20260319_162051'
    .\Discover-RC4Environment.ps1 -SendMail -MailTo "team@example.com" -SmtpServer "mail.example.com"

.NOTES
    Version : 1.4
    Datum   : 2026-03
    Ref     : https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
              https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 1000,
    [string]$ReportPath = 'C:\Temp',
    [string]$ReassessFrom,
    [switch]$SkipEvents,
    [switch]$SendMail,
    [string]$MailTo,
    [string]$MailFrom,
    [string]$SmtpServer
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
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
        'Citrix-DDC'        { 'Der Delivery Controller brokert Sessions per Kerberos. RC4 hier kann Session-Starts sporadisch stoeren.' }
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

#endregion

#region ============ PHASE 3: REPORTING ============

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
                if ($GPO.HasDES) {'KRITISCH'} elseif ($GPO.HasRC4) {'WARNUNG'} else {'OK'}
            ); Hinweis=$GPO.Recommendation
        }

        # Category summaries
        foreach ($key in @('Citrix','Igel','NonWindows','Delegation')) {
            $items = @($Discovery[$key])
            $rc4Items = @($items | Where-Object { $_.EncCategory -in @('RC4_ONLY','RC4_AES','DES_PRESENT') })
            $total = SafeCount $items
            $rc4Count = SafeCount $rc4Items
            $status = if ($rc4Count -gt 0) {'WARNUNG'} elseif ($total -gt 0) {'OK'} else {'Leer'}
            $overviewData += [PSCustomObject]@{
                Bereich=$key; Wert="$total gefunden, $rc4Count mit RC4/DES"
                Status=$status; Hinweis=''
            }
        }

        # Event summaries
        if ($Events) {
            $overviewData += [PSCustomObject]@{
                Bereich='RC4 Service Tickets'; Wert=(SafeCount $Events.RC4Tickets)
                Status=$(if ((SafeCount $Events.RC4Tickets) -gt 0) {'KRITISCH'} else {'OK'})
                Hinweis='Event 4769 mit EncType 0x17'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Pre-Auth Fehler'; Wert=(SafeCount $Events.PreAuthFails)
                Status=$(if ((SafeCount $Events.PreAuthFails) -gt 50) {'WARNUNG'} elseif ((SafeCount $Events.PreAuthFails) -gt 0) {'Info'} else {'OK'})
                Hinweis='Event 4771'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Failed Logons'; Wert=(SafeCount $Events.LogonFails)
                Status=$(if ((SafeCount $Events.LogonFails) -gt 100) {'WARNUNG'} elseif ((SafeCount $Events.LogonFails) -gt 0) {'Info'} else {'OK'})
                Hinweis='Event 4625'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Account Lockouts'; Wert=(SafeCount $Events.Lockouts)
                Status=$(if ((SafeCount $Events.Lockouts) -gt 10) {'KRITISCH'} elseif ((SafeCount $Events.Lockouts) -gt 0) {'WARNUNG'} else {'OK'})
                Hinweis='Event 4740'
            }
            $overviewData += [PSCustomObject]@{
                Bereich='Korrelierte Lockouts'; Wert=(SafeCount $Events.Correlated)
                Status=$(if ((SafeCount $Events.Correlated) -gt 0) {'KRITISCH'} else {'OK'})
                Hinweis='Kerberos-Fehler innerhalb 120s vor Lockout'
            }
        }

        $overviewData | Export-Excel -Path $xlPath -WorksheetName 'Uebersicht' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $(
            New-ConditionalText 'KRITISCH' -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
            New-ConditionalText 'WARNUNG'  -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
            New-ConditionalText 'OK'       -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
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
            Nr=1; Typ='PASSIV'; Bereich='RC4 in Accounts'
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
            Nr=1; Typ='AKTIV'; Bereich='RC4 Tickets'
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
            Nr=1; Typ='OK'; Bereich='RC4 in Accounts'
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
            Nr=2; Typ='SCHLAFEND'; Bereich='GPO erlaubt DES'
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
            Nr=2; Typ='UEBERGANG'; Bereich='GPO erlaubt RC4'
            Befund="GPO erlaubt RC4+AES (kein DES), 0 RC4-Tickets."
            Bewertung="Akzeptabler Uebergangszustand. RC4 in der GPO ist das Sicherheitsnetz waehrend Accounts auf 24 umgestellt werden."
            Bedingung="GPO auf 2147483640 (AES-only) erst setzen wenn alle Accounts auf Wert 24 und Kennwoerter rotiert."
        }
        Write-Host "  [2] UEBERGANG: GPO erlaubt RC4 aber 0 RC4-Tickets" -ForegroundColor Green
        Write-Host "      Akzeptabel. GPO auf AES-only erst nach vollstaendiger Account-Bereinigung.`n" -ForegroundColor DarkGray
    }
    elseif ($null -eq $GPO.Value -or $GPO.Value -eq 0) {
        $findings += [PSCustomObject]@{
            Nr=2; Typ='SCHLAFEND'; Bereich='GPO nicht gesetzt'
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
            Nr=3; Typ='SCHLAFEND'; Bereich='Delegation mit RC4'
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
            Nr=3; Typ='AKTIV'; Bereich='Delegation mit RC4'
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
            Nr=4; Typ='GETRENNT'; Bereich='PreAuth Fehler'
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
            Nr=4; Typ='AKTIV'; Bereich='Fallback-Kette'
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
        Nr=5; Typ='HINWEIS'; Bereich='SMB Signing'
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
            Nr=6; Typ='IMPLIZIT MITIGIERT'; Bereich='SAP Kerberos'
            Befund="0 RC4-Tickets — SAP erhaelt und akzeptiert AES-Tickets."
            Bewertung="Implizit mitigiert — wenn SAP heute mit AES funktioniert, funktioniert es auch nach DC-Account-Umstellung auf Wert 24, Server 2025 DC, und April-2026-Update."
            Bedingung="Keine weitere Aktion noetig solange der SAP Kernel nicht downgraded wird."
        }
        Write-Host "  [6] IMPLIZIT MITIGIERT: SAP" -ForegroundColor Green
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
            Nr=7; Typ='SCHLAFEND'; Bereich='Maschinenkennwort'
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
            Nr=8; Typ='SCHLAFEND'; Bereich='NOT SET Accounts'
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
    $aktiv     = @($findings | Where-Object { $_.Typ -eq 'AKTIV' })
    $schlafend = @($findings | Where-Object { $_.Typ -eq 'SCHLAFEND' })
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

#region ============ MAIN ============

if ($ReassessFrom) {
    # =============================================
    # REASSESS MODE: Load from previous CSVs
    # =============================================
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Magenta
    Write-Host "  RC4 Environment Discovery v1.4 — REASSESSMENT" -ForegroundColor Magenta
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
                    New-ConditionalText 'AKTIV'     -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
                    New-ConditionalText 'SCHLAFEND'  -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
                    New-ConditionalText 'PASSIV'    -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
                    New-ConditionalText 'MITIGIERT'  -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
                    New-ConditionalText 'GETRENNT'  -BackgroundColor '#E6F1FB' -ConditionalTextColor '#0C447C'
                    New-ConditionalText 'UEBERGANG' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
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
Write-Host "  RC4 Environment Discovery v1.4" -ForegroundColor Cyan
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
if (-not $SkipEvents) {
    $knownNames = ($allSystems | Select-Object -ExpandProperty Name) + ($deleg | Select-Object -ExpandProperty Name)
    $events = Get-RC4TicketsBySystem -MsBack $msBack -Max $MaxEvents -KnownSystems $knownNames
}

# Phase 3: Cross-check
$crossCheck = Write-Kreuzpruefung -Discovery $discovery -Events $events -GPO $gpo `
    -AllSystems $allSystems -RC4Risk $rc4Risk -DelegRC4 $delegRC4

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
                New-ConditionalText 'AKTIV'    -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F'
                New-ConditionalText 'SCHLAFEND' -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806'
                New-ConditionalText 'PASSIV'   -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
                New-ConditionalText 'MITIGIERT' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
                New-ConditionalText 'GETRENNT' -BackgroundColor '#E6F1FB' -ConditionalTextColor '#0C447C'
                New-ConditionalText 'UEBERGANG' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041'
            )
        Write-Host "  Excel-Tab    : Kreuzpruefung" -ForegroundColor Green
    }
    $crossCheck | Select-Object Nr, Typ, Bereich, Befund, Bewertung, Bedingung |
        Export-Csv (Join-Path $reportDir 'Kreuzpruefung.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "  CSV          : Kreuzpruefung.csv" -ForegroundColor Green
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
    Write-Host "  [GPO] KRITISCH: Die Kerberos-GPO erlaubt alle Verschluesselungstypen" -ForegroundColor Red
    Write-Host "         einschliesslich DES. DES ist seit 2008 gebrochen." -ForegroundColor Red
    Write-Host "         Empfehlung: GPO sofort auf 2147483644 (DES entfernen) aendern." -ForegroundColor Red
}
elseif ($gpo.HasDES) {
    Write-Host "  [GPO] KRITISCH: DES noch erlaubt. Sofort entfernen." -ForegroundColor Red
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
    Write-Host "         schlagen Authentifizierungen sporadisch fehl." -ForegroundColor Yellow
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

#endregion
