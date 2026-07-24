<#
.SYNOPSIS
  adcert demo lab seeder (minimal) - a tiny generic company sized for a
  short video demo.

.DESCRIPTION
  Creates 6 fictional employees and 4 groups under a demo OU. The resulting
  campaign is intentionally small so it is quick to walk through on camera:

      manager1     5 entries   <- the page you review in the demo
      _unrouted    1 entry     <- a grant with no owner, surfaced not dropped
      -----------------------
      6 entries total

  Planted findings, all visible on the reviewer pages:
    * jsmith  - DISABLED but still in App-Admins (privileged) and VPN-Users
    * cwlee    - contractor whose account expires in 12 days
    * bpatel  - reaches Finance-App only via a NESTED group, proving the
      collector resolves nesting instead of missing the grant
    * everyone reads "Never logged on" until you authenticate as someone

  Group names are generic corporate roles, not tied to any organization.

  DEMO LAB ONLY. Refuses to run unless the domain DNS root matches
  -ExpectedDomain (default adcert.lab). Re-runnable: existing objects are
  updated rather than duplicated. Use Remove-LabAD.ps1 to tear it down.

.EXAMPLE
  .\Seed-DemoLab.ps1

.NOTES
  Run as a Domain Admin on the lab DC. Pair with config\groups-demo.json.
#>
[CmdletBinding()]
param(
    [string]$ExpectedDomain = "adcert.lab",
    [string]$OuName         = "Demo Company",
    [string]$SeedPassword   = "Adcert-Demo-2026!"
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------- guardrail
$domain = Get-ADDomain
if ($domain.DNSRoot -ne $ExpectedDomain) {
    throw ("Refusing to run: current domain is '$($domain.DNSRoot)', expected " +
           "'$ExpectedDomain'. This seeder is for throwaway demo forests only. " +
           "Pass -ExpectedDomain to override if this really is your lab.")
}
$domainDN  = $domain.DistinguishedName
$upnSuffix = $domain.DNSRoot
$pw = ConvertTo-SecureString $SeedPassword -AsPlainText -Force

# ---------------------------------------------------------------------- OU
$ouDN = "OU=$OuName,$domainDN"
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $OuName -Path $domainDN `
        -ProtectedFromAccidentalDeletion $false
    Write-Host "[+] Created OU: $ouDN"
} else {
    Write-Host "[=] OU exists: $ouDN"
}

# ------------------------------------------------------------------- people
# sam, first, last, title, dept, managerSam ('' = no manager -> _unrouted)
$people = @(
    @('manager1','Dana','Reed','Team Manager','Operations',''),
    @('awong','Alex','Wong','Analyst','Finance','manager1'),
    @('jsmith','Jordan','Smith','Analyst','Operations','manager1'),
    @('cwlee','Casey','Lee','Contractor','Operations','manager1'),
    @('bpatel','Bailey','Patel','Associate','Finance','manager1'),
    @('rkim','Riley','Kim','Coordinator','Operations','')
)

foreach ($p in $people) {
    $sam,$first,$last,$title,$dept,$mgr = $p
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "$first $last" -GivenName $first -Surname $last `
            -SamAccountName $sam -UserPrincipalName "$sam@$upnSuffix" `
            -DisplayName "$first $last" -Title $title -Department $dept `
            -Path $ouDN -AccountPassword $pw -Enabled $true `
            -PasswordNeverExpires $true -ChangePasswordAtLogon $false
        Write-Host "[+] User: $sam ($first $last, $title)"
    } else {
        Set-ADUser -Identity $sam -Title $title -Department $dept -Enabled $true
        Clear-ADAccountExpiration -Identity $sam -ErrorAction SilentlyContinue
        Write-Host "[=] User exists, reset: $sam"
    }
}

foreach ($p in $people) {
    $sam,$null,$null,$null,$null,$mgr = $p
    if ($mgr) { Set-ADUser -Identity $sam -Manager (Get-ADUser $mgr) }
    else      { Set-ADUser -Identity $sam -Clear manager }
}
Write-Host "[+] Manager chains set (manager1 reviews; rkim has no manager on purpose)"

# ------------------------------------------------------------------- groups
$groups = @(
    @('Finance-App',    'Access to the finance application'),
    @('VPN-Users',      'Remote VPN access'),
    @('App-Admins',     'Application administrator rights (privileged)'),
    @('Finance-Team',   'Nested group - finance department staff')
)
foreach ($g in $groups) {
    $name,$desc = $g
    if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $name -GroupScope Global -GroupCategory Security `
            -Path $ouDN -Description $desc
        Write-Host "[+] Group: $name"
    } else {
        Write-Host "[=] Group exists: $name"
    }
}

function Set-Members {
    param([string]$Group, [string[]]$Sams)
    $current = @(Get-ADGroupMember -Identity $Group -ErrorAction SilentlyContinue |
                 Where-Object objectClass -eq 'user' |
                 ForEach-Object { $_.SamAccountName })
    foreach ($c in $current) {
        if ($Sams -notcontains $c) {
            Remove-ADGroupMember -Identity $Group -Members $c -Confirm:$false
        }
    }
    foreach ($s in $Sams) {
        if ($current -notcontains $s) {
            Add-ADGroupMember -Identity $Group -Members $s -ErrorAction SilentlyContinue
        }
    }
}

Set-Members 'Finance-Team' @('bpatel')
Set-Members 'Finance-App'  @('awong')
Set-Members 'VPN-Users'    @('jsmith','cwlee','rkim')
Set-Members 'App-Admins'   @('jsmith')

# nested: finance team reaches Finance-App only through Finance-Team
Add-ADGroupMember -Identity 'Finance-App' `
    -Members (Get-ADGroup 'Finance-Team') -ErrorAction SilentlyContinue
Write-Host "[+] Memberships set (Finance-Team nested inside Finance-App)"

# --------------------------------------------------------- planted findings
Disable-ADAccount -Identity jsmith
Write-Host "[!] PLANTED: jsmith DISABLED but still in App-Admins and VPN-Users"

Set-ADAccountExpiration -Identity cwlee -DateTime (Get-Date).AddDays(12)
Write-Host "[!] PLANTED: cwlee (Contractor) account expires in 12 days"

Write-Host "[!] PLANTED: bpatel reaches Finance-App only via the nested group"
Write-Host "[!] PLANTED: all seeded users read 'Never logged on' until first authentication"

# ------------------------------------------------------------------ summary
Write-Host ""
Write-Host "=== Demo lab ready: 6 users, 6 access grants ==="
Write-Host "    Expected review packages:"
Write-Host "      manager1     5 entries   (jsmith x2, cwlee, awong, bpatel)"
Write-Host "      _unrouted    1 entry     (rkim - no manager set)"
Write-Host ""
Write-Host "    NEXT STEPS"
Write-Host "    1. Optional, for a 'logged on today' contrast on the review page:"
Write-Host "         `$c = Get-Credential adcert\awong   # password: $SeedPassword"
Write-Host "         New-PSSession -ComputerName localhost -Credential `$c | Remove-PSSession"
Write-Host "    2. Build the campaign:"
Write-Host "         .\New-AdcertCampaign.ps1 -Config ..\config\groups-demo.json -OutDir C:\adcert\UAR-Demo" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Tear the lab down again with .\Remove-LabAD.ps1"
