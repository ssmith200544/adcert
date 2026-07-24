<#
.SYNOPSIS
  adcert demo lab seeder - populates a throwaway AD forest with a fake
  research-enclave org and planted review findings.

.DESCRIPTION
  Creates, under a dedicated OU:
    * 15 fictional users with titles, departments, and manager chains
    * the four enclave groups matching config/groups.json
    * planted findings the review should surface:
        - a DISABLED account still holding Enclave-Admins membership
        - never-logged-on accounts (all seeded users until you log one on)
        - a contractor whose accountExpires lands ~12 days out
        - a nested group (Enclave-GradStudents inside Enclave-HPC-Users) to prove
          the collector's recursive resolution

  DEMO LAB ONLY. Do not run against a production domain. The script refuses
  to run unless the domain DNS root matches -ExpectedDomain (default adcert.lab).

  All names are fictional and match the labgen synthetic name pool, so demo
  footage stays consistent between synthetic mode and the VM.

.EXAMPLE
  .\Seed-LabAD.ps1
  .\Seed-LabAD.ps1 -ExpectedDomain adcert.lab -OuName "Research Enclave"

.NOTES
  Run as a Domain Admin on the lab DC. Re-runnable: existing objects are
  updated rather than duplicated.
#>
[CmdletBinding()]
param(
    [string]$ExpectedDomain = "adcert.lab",
    [string]$OuName         = "Research Enclave",
    # Demo-lab-only credential for all seeded accounts (interactive logon
    # of a couple of users populates lastLogonTimestamp for the demo).
    [string]$SeedPassword   = "Adcert-Demo-2026!"
)

Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------- guardrail
$domain = Get-ADDomain
if ($domain.DNSRoot -ne $ExpectedDomain) {
    throw ("Refusing to run: current domain is '$($domain.DNSRoot)', expected " +
           "'$ExpectedDomain'. This seeder is for throwaway demo forests only. " +
           "Pass -ExpectedDomain to override if this really is your lab.")
}
$domainDN = $domain.DistinguishedName
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
# sam, first, last, title, dept, managerSam ('' = top of chain)
$people = @(
    @('alindqvist','Avery','Lindqvist','PI','Aerospace Eng',''),
    @('costrom','Casey','Ostrom','PI','Mech Eng',''),
    @('khaddad','Kendall','Haddad','PI','ECE',''),
    @('jvang','Jordan','Vang','Lab Manager','Aerospace Eng','alindqvist'),
    @('rchen','Riley','Chen','Research Scientist','Aerospace Eng','alindqvist'),
    @('mnovak','Morgan','Novak','Postdoc','Aerospace Eng','alindqvist'),
    @('qokafor','Quinn','Okafor','Graduate RA','Mech Eng','costrom'),
    @('rbergstrom','Rowan','Bergstrom','Research Engineer','Mech Eng','costrom'),
    @('eiwu','Emerson','Iwu','Graduate RA','Mech Eng','costrom'),
    @('skowalski','Skyler','Kowalski','Data Analyst','ECE','khaddad'),
    @('dpetrov','Dakota','Petrov','Research Scientist','ECE','khaddad'),
    @('rdelaney','Reese','Delaney','Postdoc','ECE','khaddad'),
    @('fmoreno','Finley','Moreno','Graduate RA','Aerospace Eng','alindqvist'),
    @('haskari','Harper','Askari','Contractor','Mech Eng','costrom'),      # expiring
    @('sbyrne','Sage','Byrne','Research Scientist','Physics','khaddad')    # to disable
)

foreach ($p in $people) {
    $sam,$first,$last,$title,$dept,$mgr = $p
    $existing = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ADUser -Name "$first $last" -GivenName $first -Surname $last `
            -SamAccountName $sam -UserPrincipalName "$sam@$upnSuffix" `
            -DisplayName "$first $last" -Title $title -Department $dept `
            -Path $ouDN -AccountPassword $pw -Enabled $true `
            -PasswordNeverExpires $true -ChangePasswordAtLogon $false
        Write-Host "[+] User: $sam ($first $last, $title)"
    } else {
        Set-ADUser -Identity $sam -Title $title -Department $dept
        Write-Host "[=] User exists, updated: $sam"
    }
}

# second pass: manager links (all users must exist first)
foreach ($p in $people) {
    $sam,$null,$null,$null,$null,$mgr = $p
    if ($mgr) { Set-ADUser -Identity $sam -Manager (Get-ADUser $mgr) }
}
Write-Host "[+] Manager chains set (3 PIs at top, no manager -> _unrouted demo)"

# ------------------------------------------------------------------- groups
# name, description  (plain_language lives in config/groups.json, not AD)
$groups = @(
    @('Enclave-HPC-Users',  'SSH access to enclave HPC compute nodes'),
    @('Enclave-Storage-RW', 'Read/write on TrueNAS CUI shares'),
    @('Enclave-VPN-Access', 'Enclave VPN remote access'),
    @('Enclave-Admins',     'Enclave administrative access (privileged)'),
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

function Add-Members { param($Group, $Sams)
    Add-ADGroupMember -Identity $Group -Members $Sams -ErrorAction SilentlyContinue
}

# nested group membership - proves recursive resolution in the collector
Add-Members 'Enclave-GradStudents' @('qokafor','eiwu','fmoreno')
Add-ADGroupMember -Identity 'Enclave-HPC-Users' -Members (Get-ADGroup 'Enclave-GradStudents') `
    -ErrorAction SilentlyContinue

Add-Members 'Enclave-HPC-Users'  @('alindqvist','costrom','jvang','rchen','mnovak',
                               'rbergstrom','skowalski','dpetrov','sbyrne','haskari')
Add-Members 'Enclave-Storage-RW' @('alindqvist','costrom','khaddad','jvang','rchen',
                               'qokafor','rbergstrom','skowalski','rdelaney','fmoreno')
Add-Members 'Enclave-VPN-Access' @('alindqvist','khaddad','rchen','mnovak','dpetrov',
                               'rdelaney','haskari')
Add-Members 'Enclave-Admins'     @('alindqvist','jvang','sbyrne')
Write-Host "[+] Memberships assigned (incl. nested Enclave-GradStudents -> Enclave-HPC-Users)"

# --------------------------------------------------------- planted findings
# Finding 1: disabled account still in the privileged group + HPC
Disable-ADAccount -Identity sbyrne
Write-Host "[!] PLANTED: sbyrne DISABLED but still a member of Enclave-Admins and Enclave-HPC-Users"

# Finding 2: contractor expiring ~12 days out
Set-ADAccountExpiration -Identity haskari -DateTime (Get-Date).AddDays(12)
Write-Host "[!] PLANTED: haskari (Contractor) accountExpires in 12 days"

# Finding 3: never-logged-on accounts - automatic; every seeded user shows
# 'Never logged on' until someone interactively logs on as them.
Write-Host "[!] PLANTED: all seeded users read as 'Never logged on' until first logon"

Write-Host ""
Write-Host "=== Seeding complete ==="
Write-Host "Next steps for the demo:"
Write-Host "  1. (Optional) Log on interactively as 1-2 users (e.g. rchen, jvang)"
Write-Host "     with password '$SeedPassword' so lastLogonTimestamp populates"
Write-Host "     and the review shows a mix of recent activity and 'never'."
Write-Host "  2. Run the collector:"
Write-Host "     .\Collect-AccessSnapshot.ps1 -Config ..\config\groups.json -Out snapshot.json"
Write-Host "  3. Confirm the snapshot surfaces sbyrne (disabled, privileged),"
Write-Host "     haskari (expiring), and the nested grad students inside Enclave-HPC-Users."
