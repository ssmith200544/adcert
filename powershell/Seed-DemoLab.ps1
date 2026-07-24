<#
.SYNOPSIS
  adcert demo lab seeder (small) - a deliberately tiny org sized for a video demo.

.DESCRIPTION
  Creates 9 fictional users and 5 groups under a demo OU. The resulting
  campaign is small enough to walk through on camera:

      alindqvist   6 entries   <- the page you review in the demo
      costrom      3 entries   <- proves routing splits by supervisor
      _unrouted    2 entries   <- grants with no owner, surfaced not dropped
      ------------------------
      11 entries total

  Planted findings, all visible on the reviewer pages:
    * sbyrne  - DISABLED but still in Enclave-Admins (privileged) and HPC
    * haskari - contractor whose account expires in 12 days
    * fmoreno / qokafor - HPC access only via a NESTED group, proving the
      collector resolves nesting instead of missing the grant
    * everyone reads "Never logged on" until you authenticate as someone

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
    [string]$OuName         = "Research Enclave",
    # Demo-lab-only credential for all seeded accounts.
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
    @('alindqvist','Avery','Lindqvist','Principal Investigator','Aerospace Eng',''),
    @('costrom','Casey','Ostrom','Principal Investigator','Mech Eng',''),
    @('rchen','Riley','Chen','Research Scientist','Aerospace Eng','alindqvist'),
    @('sbyrne','Sage','Byrne','Research Scientist','Physics','alindqvist'),
    @('haskari','Harper','Askari','Contractor','Mech Eng','alindqvist'),
    @('fmoreno','Finley','Moreno','Graduate RA','Aerospace Eng','alindqvist'),
    @('qokafor','Quinn','Okafor','Graduate RA','Mech Eng','costrom'),
    @('dpetrov','Dakota','Petrov','Research Scientist','ECE','costrom'),
    @('jvang','Jordan','Vang','Lab Manager','Aerospace Eng','')
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

# second pass: manager links (all users must exist first)
foreach ($p in $people) {
    $sam,$null,$null,$null,$null,$mgr = $p
    if ($mgr) { Set-ADUser -Identity $sam -Manager (Get-ADUser $mgr) }
    else      { Set-ADUser -Identity $sam -Clear manager }
}
Write-Host "[+] Manager chains set (2 PIs review; jvang has no manager on purpose)"

# ------------------------------------------------------------------- groups
$groups = @(
    @('Enclave-HPC-Users',   'SSH access to enclave HPC compute nodes'),
    @('Enclave-Storage-RW',  'Read/write on the CUI project shares'),
    @('Enclave-VPN-Access',  'Enclave VPN remote access'),
    @('Enclave-Admins',      'Enclave administrative access (privileged)'),
    @('Enclave-GradStudents','Nested group - graduate research assistants')
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
    # make membership exactly match the list, so re-runs stay deterministic
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

Set-Members 'Enclave-GradStudents' @('fmoreno','qokafor')
Set-Members 'Enclave-HPC-Users'    @('rchen','sbyrne','haskari')
Set-Members 'Enclave-Storage-RW'   @('rchen','qokafor')
Set-Members 'Enclave-VPN-Access'   @('dpetrov','jvang')
Set-Members 'Enclave-Admins'       @('sbyrne','jvang')

# nested: grad students reach HPC only through Enclave-GradStudents
Add-ADGroupMember -Identity 'Enclave-HPC-Users' `
    -Members (Get-ADGroup 'Enclave-GradStudents') -ErrorAction SilentlyContinue
Write-Host "[+] Memberships set (Enclave-GradStudents nested inside Enclave-HPC-Users)"

# --------------------------------------------------------- planted findings
Disable-ADAccount -Identity sbyrne
Write-Host "[!] PLANTED: sbyrne DISABLED but still in Enclave-Admins and Enclave-HPC-Users"

Set-ADAccountExpiration -Identity haskari -DateTime (Get-Date).AddDays(12)
Write-Host "[!] PLANTED: haskari (Contractor) account expires in 12 days"

Write-Host "[!] PLANTED: grad students reach HPC only via the nested group"
Write-Host "[!] PLANTED: all seeded users read 'Never logged on' until first authentication"

# ------------------------------------------------------------------ summary
Write-Host ""
Write-Host "=== Demo lab ready: 9 users, 11 access grants ==="
Write-Host "    Expected review packages:"
Write-Host "      alindqvist   6 entries   (sbyrne x2, haskari, fmoreno, rchen x2)"
Write-Host "      costrom      3 entries   (qokafor x2, dpetrov)"
Write-Host "      _unrouted    2 entries   (jvang - no manager set)"
Write-Host ""
Write-Host "    NEXT STEPS"
Write-Host "    1. Optional, for a 'logged on today' contrast on the review page:"
Write-Host "         `$c = Get-Credential adcert\rchen   # password: $SeedPassword"
Write-Host "         New-PSSession -ComputerName localhost -Credential `$c | Remove-PSSession"
Write-Host "    2. Build the campaign:"
Write-Host "         .\New-AdcertCampaign.ps1 -Config ..\config\groups-demo.json -OutDir C:\adcert\UAR-Demo" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Tear the lab down again with .\Remove-LabAD.ps1"
