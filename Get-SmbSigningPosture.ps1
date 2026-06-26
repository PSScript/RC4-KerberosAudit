#Requires -Version 5.1
<#
.SYNOPSIS
    Berichtet den SMB-Signing-Status je Server: Audit-Aktivierung
    (AuditClientDoesNotSupportSigning) GEGEN tatsaechliches Signing-Enforcement
    (RequireSecuritySignature) — Server- und Client-seitig.

.DESCRIPTION
    Liest je Zielsystem authoritativ aus der Registry (versionsunabhaengig) und
    reichert — sofern vorhanden — via Get-SmbServerConfiguration /
    Get-SmbClientConfiguration an:

    Server  (LanmanServer\Parameters):
      - RequireSecuritySignature           Enforcement: Signing erzwungen
      - EnableSecuritySignature            Legacy, ab SMB2 ignoriert (nur Info)
      - AuditClientDoesNotSupportSigning   Audit-Schalter (ab Sept-2025-Update / KB5066913)
      - AuditClientSpnSupport              EPA/SPN-Audit (zur Vollstaendigkeit)
    Client  (LanmanWorkstation\Parameters):
      - RequireSecuritySignature
      - EnableSecuritySignature            Legacy

    Zweck: VOR dem Enforcement-Update auf den DCs bestaetigen, dass die korrekte
    Discovery-Phase aktiv ist — Audit AN, Enforcement AUS — und feststellen,
    welche Systeme das Audit ueberhaupt unterstuetzen (Patch-Stand).

    Die Audit-Faehigkeit wird daran erkannt, ob Get-SmbServerConfiguration die
    Eigenschaft AuditClientDoesNotSupportSigning bereitstellt. Fehlt sie, ist das
    Sept-2025-Update (CVE-2025-55234 / KB5066913) noch nicht installiert.

    Read-only. Aktiviert nichts. Aktivierungsbefehle siehe .NOTES.

.PARAMETER TargetScope
    DiscoveredOnly (Standard: nur Domain Controller — die das Update zuerst erzwingen),
    AllServers (DCs + Mitgliedsserver) oder Full (inkl. Workstations).

.PARAMETER ComputerName
    Explizite Zielliste. Ueberschreibt die TargetScope-Discovery.

.PARAMETER ReportPath
    Zielordner fuer den Report. Standard: C:\Temp

.PARAMETER SkipRemoteCheck
    Nur lokales System pruefen, kein WinRM.

.PARAMETER ImportOnly
    Nur Funktionen laden, kein Scan.

.EXAMPLE
    .\Get-SmbSigningPosture.ps1
    .\Get-SmbSigningPosture.ps1 -TargetScope AllServers
    .\Get-SmbSigningPosture.ps1 -ComputerName DC01,FS01,FS02
    .\Get-SmbSigningPosture.ps1 -SkipRemoteCheck

.NOTES
    Version  : 1.0
    Kontext  : SMB Server Signing Hardening — Audit-vor-Enforcement
    Referenz : KB5066913 (CVE-2025-55234) — Audit-Events ab Sept-2025-Update
               HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AuditClientDoesNotSupportSigning (REG_DWORD)
               GPO: Computer\Administrative Templates\Network\Lanman Server\"Audit client does not support signing"
    Events   : 3021 (SMB2/3), 3027 (SMB1) in Microsoft-Windows-SMBServer/Audit
    Folgesatz: Nach Audit-Aktivierung Betroffene sammeln mit Find-SmbSigningExposure.ps1
    Annahme  : Audit-Faehigkeit wird aus der Cmdlet-Eigenschaft abgeleitet; meldet ein
               gepatchtes System faelschlich "nicht faehig", Eigenschaftsnamen pruefen.

    Audit aktivieren (eine der drei Varianten):
      PowerShell : Set-SmbServerConfiguration -AuditClientDoesNotSupportSigning $true
      Registry   : New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AuditClientDoesNotSupportSigning -Value 1 -PropertyType DWord -Force
      GPO        : s.o. (gilt fuer SMBv1- und SMB2/3-Server)
#>

[CmdletBinding()]
param(
    [ValidateSet('DiscoveredOnly','AllServers','Full')]
    [string]$TargetScope = 'DiscoveredOnly',
    [string[]]$ComputerName,
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
$reportDir = Join-Path $ReportPath "SMBSign_${domainShort}_${ts}"

#region ============ HELPERS ============

function SafeCount { param($C) if ($null -eq $C) {0} elseif ($C -is [array]) {$C.Length} else {1} }

function Write-Status {
    param([string]$Label, [string]$Value, [string]$Color = 'White')
    Write-Host "  $($Label.PadRight(34)) $Value" -ForegroundColor $Color
}

function Get-SeverityColor {
    param([string]$Bewertung)
    switch -Regex ($Bewertung) {
        '^Fehler'      { 'Red'    ; break }
        '^Warnung'     { 'Yellow' ; break }
        '^Information' { 'Green'  ; break }
        default        { 'Gray' }
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

# Self-contained Probe — laeuft lokal oder via Invoke-Command (keine Outer-Variablen).
$script:SigningProbe = {
    $out = [ordered]@{
        Srv_RequireSigning_Reg = $null; Srv_EnableSigning_Reg = $null
        Srv_AuditSigning_Reg   = $null; Srv_AuditSpn_Reg      = $null
        Cli_RequireSigning_Reg = $null; Cli_EnableSigning_Reg = $null
        Srv_RequireSigning_Cmd = $null; Srv_EnableSigning_Cmd = $null
        Srv_AuditSigning_Cmd   = $null
        Srv_EncryptData        = $null; Srv_RejectUnencrypted = $null; Srv_SMB1Enabled = $null
        Cli_RequireSigning_Cmd = $null; Cli_EnableSigning_Cmd = $null
        AuditCapable           = $false
        OS = $null; Build = $null; IsDC = $null
    }

    function _RegVal {
        param([string]$Path, [string]$Name)
        try { (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch { $null }
    }

    $srvKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wkKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    $out['Srv_RequireSigning_Reg'] = _RegVal $srvKey 'RequireSecuritySignature'
    $out['Srv_EnableSigning_Reg']  = _RegVal $srvKey 'EnableSecuritySignature'
    $out['Srv_AuditSigning_Reg']   = _RegVal $srvKey 'AuditClientDoesNotSupportSigning'
    $out['Srv_AuditSpn_Reg']       = _RegVal $srvKey 'AuditClientSpnSupport'
    $out['Cli_RequireSigning_Reg'] = _RegVal $wkKey  'RequireSecuritySignature'
    $out['Cli_EnableSigning_Reg']  = _RegVal $wkKey  'EnableSecuritySignature'

    try {
        $sc = Get-SmbServerConfiguration -EA Stop
        $out['Srv_RequireSigning_Cmd'] = [bool]$sc.RequireSecuritySignature
        $out['Srv_EnableSigning_Cmd']  = [bool]$sc.EnableSecuritySignature
        $out['Srv_EncryptData']        = [bool]$sc.EncryptData
        $out['Srv_RejectUnencrypted']  = [bool]$sc.RejectUnencryptedAccess
        if ($sc.PSObject.Properties.Name -contains 'EnableSMB1Protocol') {
            $out['Srv_SMB1Enabled'] = [bool]$sc.EnableSMB1Protocol
        }
        if ($sc.PSObject.Properties.Name -contains 'AuditClientDoesNotSupportSigning') {
            $out['AuditCapable']         = $true
            $out['Srv_AuditSigning_Cmd'] = [bool]$sc.AuditClientDoesNotSupportSigning
        }
    } catch {}

    try {
        $cc = Get-SmbClientConfiguration -EA Stop
        $out['Cli_RequireSigning_Cmd'] = [bool]$cc.RequireSecuritySignature
        $out['Cli_EnableSigning_Cmd']  = [bool]$cc.EnableSecuritySignature
    } catch {}

    try {
        $os = Get-CimInstance Win32_OperatingSystem -EA Stop
        $out['OS'] = $os.Caption; $out['Build'] = $os.BuildNumber
    } catch {}
    try {
        $csi = Get-CimInstance Win32_ComputerSystem -EA Stop
        $out['IsDC'] = ($csi.DomainRole -in 4,5)
    } catch {}

    [PSCustomObject]$out
}

function Resolve-SigningRow {
    param([string]$Computer, $Probe)

    function _Pick { param($Cmd, $Reg) if ($null -ne $Cmd) { [bool]$Cmd } elseif ($null -ne $Reg) { [bool]([int]$Reg) } else { $null } }

    $auditCapable = [bool]$Probe.AuditCapable
    $srvReq   = _Pick $Probe.Srv_RequireSigning_Cmd $Probe.Srv_RequireSigning_Reg
    $srvAudit = _Pick $Probe.Srv_AuditSigning_Cmd   $Probe.Srv_AuditSigning_Reg
    $cliReq   = _Pick $Probe.Cli_RequireSigning_Cmd $Probe.Cli_RequireSigning_Reg
    $srvEnLeg = _Pick $Probe.Srv_EnableSigning_Cmd  $Probe.Srv_EnableSigning_Reg
    $spnAudit = if ($null -ne $Probe.Srv_AuditSpn_Reg) { [bool]([int]$Probe.Srv_AuditSpn_Reg) } else { $null }
    $smb1     = $Probe.Srv_SMB1Enabled

    $bewertung =
        if (-not $auditCapable) {
            'Fehler — Audit nicht verfuegbar (Sept-2025-Update/KB5066913 fehlt). Discovery-Phase nicht moeglich.'
        }
        elseif ($srvAudit -and ($srvReq -ne $true)) {
            'Information — Discovery-Phase aktiv (Audit AN, Enforcement AUS). Korrekt vor dem Update.'
        }
        elseif ($srvAudit -and ($srvReq -eq $true)) {
            'Warnung — Enforcement bereits aktiv trotz Audit. Inkompatible Clients werden schon jetzt abgewiesen.'
        }
        elseif ((-not $srvAudit) -and ($srvReq -ne $true)) {
            'Warnung — Weder Audit noch Enforcement. Audit aktivieren, um Betroffene zu finden.'
        }
        else {
            'Fehler — Enforcement ohne vorherige Audit-Phase. Blindes Enforcement-Risiko.'
        }

    if ($smb1 -eq $true -and $auditCapable) {
        $bewertung += ' Hinweis: SMBv1-Server aktiv — Event 3027 kann erscheinen, ist aber unzuverlaessig.'
    }

    [PSCustomObject][ordered]@{
        ComputerName             = $Computer
        IsDC                     = $Probe.IsDC
        OS                       = $Probe.OS
        Build                    = $Probe.Build
        AuditCapable             = $auditCapable
        Srv_AuditSigning         = $srvAudit
        Srv_RequireSigning       = $srvReq
        Srv_EnableSigning_Legacy = $srvEnLeg
        Cli_RequireSigning       = $cliReq
        Srv_AuditSPN_EPA         = $spnAudit
        Srv_EncryptData          = $Probe.Srv_EncryptData
        Srv_RejectUnencrypted    = $Probe.Srv_RejectUnencrypted
        Srv_SMB1Enabled          = $smb1
        Bewertung                = $bewertung
    }
}

#endregion

#region ============ REPORT ============

function Export-SigningReport {
    param([array]$Rows, [string]$Path)

    if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }

    if ((SafeCount $Rows) -gt 0) {
        $Rows | Export-Csv (Join-Path $Path 'SMBSigning_Posture.csv') -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  CSV: SMBSigning_Posture.csv ($(SafeCount $Rows))" -ForegroundColor Green
    }

    $hasExcel = $false
    try { Import-Module ImportExcel -EA Stop; $hasExcel = $true } catch {}
    if ($hasExcel -and (SafeCount $Rows) -gt 0) {
        $xl = Join-Path $Path "SMBSigning_${domainShort}_Posture.xlsx"
        $ct = @(
            (New-ConditionalText 'Fehler'      -BackgroundColor '#FCEBEB' -ConditionalTextColor '#791F1F')
            (New-ConditionalText 'Warnung'     -BackgroundColor '#FFF8E1' -ConditionalTextColor '#633806')
            (New-ConditionalText 'Information' -BackgroundColor '#E1F5EE' -ConditionalTextColor '#085041')
        )
        $Rows | Export-Excel -Path $xl -WorksheetName 'Posture' -AutoSize -FreezeTopRow -BoldTopRow -ConditionalText $ct
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
    Write-Host "    Get-TargetServers   Resolve-SigningRow   Export-SigningReport" -ForegroundColor DarkGray
}
elseif (-not $script:_IsDotSourced) {

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  SMB Signing Posture v1.0  (Audit vs Enforcement)" -ForegroundColor Cyan
    Write-Host "  Domaene: $domainFQDN ($domainShort)" -ForegroundColor Cyan
    Write-Host "  Scope: $TargetScope" -ForegroundColor Cyan
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

    $rows = @()
    $i = 0
    foreach ($t in $targets) {
        $i++
        $c = $t.DNSHostName
        Write-Host ("`n[{0}/{1}] {2}" -f $i, (SafeCount $targets), $c) -ForegroundColor Cyan
        $isLocal = ($c -eq $env:COMPUTERNAME) -or ($c -eq 'localhost') -or ($c -eq '.')
        try {
            if ($isLocal -or $SkipRemoteCheck) {
                $probe = & $script:SigningProbe
            } else {
                $probe = Invoke-Command -ComputerName $c -ScriptBlock $script:SigningProbe -EA Stop
            }
            $row = Resolve-SigningRow -Computer $c -Probe $probe
            $rows += $row
            Write-Status 'Audit faehig'    ([string]$row.AuditCapable)
            Write-Status 'Audit Signing'   ([string]$row.Srv_AuditSigning)
            Write-Status 'Server erzwingt'  ([string]$row.Srv_RequireSigning)
            Write-Host ("  {0}" -f $row.Bewertung) -ForegroundColor (Get-SeverityColor $row.Bewertung)
        } catch {
            Write-Host "  Nicht erreichbar / Fehler: $_" -ForegroundColor Red
            $rows += [PSCustomObject][ordered]@{
                ComputerName = $c; IsDC = $null; OS = $null; Build = $null
                AuditCapable = $null; Srv_AuditSigning = $null; Srv_RequireSigning = $null
                Srv_EnableSigning_Legacy = $null; Cli_RequireSigning = $null; Srv_AuditSPN_EPA = $null
                Srv_EncryptData = $null; Srv_RejectUnencrypted = $null; Srv_SMB1Enabled = $null
                Bewertung = "Fehler — nicht erreichbar: $($_.Exception.Message)"
            }
        }
    }

    Write-Host "`n=== ERGEBNIS ===" -ForegroundColor Cyan
    $rows | Sort-Object Bewertung | Format-Table ComputerName, IsDC, AuditCapable, Srv_AuditSigning, Srv_RequireSigning, Cli_RequireSigning -AutoSize

    Export-SigningReport -Rows $rows -Path $reportDir

    Write-Host "`nFertig. Nach aktivem Audit Betroffene sammeln mit:" -ForegroundColor Cyan
    Write-Host "  .\Find-SmbSigningExposure.ps1 -TargetScope $TargetScope -Hours 168" -ForegroundColor Gray
}

#endregion
