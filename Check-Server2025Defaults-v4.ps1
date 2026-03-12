#Requires -Version 5.1
<#
.SYNOPSIS
    Prueft Windows Server 2025 Sicherheits-Defaults mit AD-nativer Erkennung.

.DESCRIPTION
    v4.0 - Vollstaendige Analyse: SMB + LDAP + Kerberos RC4/AES + NTLM

    Server 2025 aendert vier Sicherheits-Defaults gleichzeitig:
    1. SMB Signierung standardmaessig erzwungen (Kaskade: SYSVOL->GPO->Kerberos->Auth)
    2. LDAP Signierung bei Neuinstallationen erzwungen
    3. RC4 Kerberos TGTs werden von 2025 DCs nicht mehr ausgestellt
    4. NTLM Einschraenkungen verschaerft

    In gemischten Umgebungen fuehrt dies zu Anmeldefehlern und
    Replikationsproblemen. Die Ursache ist Konfiguration, nicht das Image.

    Drei Phasen:
    Phase 1  : AD-native Rollenerkennung (kein WinRM)
    Phase 1.5: Kerberos Verschluesselungs-Audit aus AD (msDS-SupportedEncryptionTypes)
               Findet RC4-only Accounts, fehlende AES-Keys, gMSAs
    Phase 2  : Remote SMB/LDAP/NTLM/Kerberos Policy-Pruefung (WinRM)

.PARAMETER Scope
    'DomainControllers', 'MemberServers', or 'All' (default: All)

.PARAMETER ExportCsv
    Path to export results as CSV.

.PARAMETER SkipRemoteCheck
    Only run Phase 1 + 1.5 (AD discovery + Kerberos audit). No WinRM.

.EXAMPLE
    .\Check-Server2025Defaults-v4.ps1
    .\Check-Server2025Defaults-v4.ps1 -SkipRemoteCheck
    .\Check-Server2025Defaults-v4.ps1 -ExportCsv "C:\Temp\Audit.csv"
    .\Check-Server2025Defaults-v4.ps1 -KerberosScope DiscoveredOnly   # default: only Phase 1 servers (~141)
    .\Check-Server2025Defaults-v4.ps1 -KerberosScope AllServers       # all server OS accounts
    .\Check-Server2025Defaults-v4.ps1 -KerberosScope Full             # entire domain (5000+ objects, SOC alert!)

.NOTES
    Datum   : 2026-03-09
    Version : 4.2
    Zweck   : Prueft ob die Umgebung fuer Server 2025 bereit ist.
              Server 2025 erzwingt SMB Signierung, Kerberos AES-only und
              LDAP Signierung. In gemischten Umgebungen fuehrt das zu
              Anmeldefehlern und Replikationsproblemen.
    Aenderungen: v4.2 - KerberosScope Parameter (DiscoveredOnly/AllServers/Full)
                        um SOC-Alerts bei grossflaechigem Scan zu vermeiden.
                 v4.1 - UNREACHABLE falsch als 2025 erkannt, CA nutzt Hostnamen
                 statt Zertifikatsname, CNOs als ClusterVNO getaggt,
                 DAG CNOs korrekt als ExchangeDAG erkannt.
    Ref     : https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/
              https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
              https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025
              https://borncity.com/blog/2025/09/27/windows-server-2025-als-dc-finger-weg-bei-gemischten-umgebungen-rc4-problem/
              https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/
#>

[CmdletBinding()]
param(
    [ValidateSet('DomainControllers', 'MemberServers', 'All')]
    [string]$Scope = 'All',
    [string]$ExportCsv,
    [switch]$SkipRemoteCheck,

    [ValidateSet('DiscoveredOnly', 'AllServers', 'Full')]
    [string]$KerberosScope = 'DiscoveredOnly'
    # DiscoveredOnly = nur Server aus Phase 1 (DC, Exchange, CA, Cluster, DFS, HyperV) (Standard)
    # AllServers     = alle Computer-Accounts mit OperatingSystem *Server*
    # Full           = gesamte Domaene: alle Computer, Service Accounts, gMSAs, Trusts (5000+ Objekte)
)

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

#endregion

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
$reportDir = 'C:\Temp'
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
