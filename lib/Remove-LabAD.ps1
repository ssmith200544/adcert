<#
.SYNOPSIS
  adcert demo lab teardown - removes everything a seeder script created.

.DESCRIPTION
  Deletes the demo OU and everything inside it (users, groups, memberships),
  then sweeps for any known lab groups that were moved outside the OU.

  DEMO LAB ONLY. Refuses to run unless the domain DNS root matches
  -ExpectedDomain (default adcert.lab). Shows a full inventory of what it
  is about to delete and requires you to type DELETE to proceed, unless
  -Force is passed.

  Safe to run more than once; anything already gone is simply skipped.

.EXAMPLE
  .\adcert.ps1 lab remove

.EXAMPLE
  .\adcert.ps1 lab remove -Force

.NOTES
  Run as a Domain Admin on the lab DC.
#>
[CmdletBinding()]
param(
    [string]$ExpectedDomain = "adcert.lab",
    # current demo OU first; the rest are legacy names from earlier seeder
    # versions, kept so this can clean up a VM seeded before the rename
    [string[]]$OuName = @("Demo Company", "Research Enclave", "SDC Enclave", "Demo Enclave"),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------- guardrail
$domain = Get-ADDomain
if ($domain.DNSRoot -ne $ExpectedDomain) {
    throw ("Refusing to run: current domain is '$($domain.DNSRoot)', expected " +
           "'$ExpectedDomain'. This teardown is for throwaway demo forests only. " +
           "Pass -ExpectedDomain to override if this really is your lab.")
}
$domainDN = $domain.DistinguishedName

# known lab group names, for the post-teardown sweep
# current demo group names first; the Enclave-* / SDC-* entries are legacy
# names from earlier seeder versions, swept up here for the same reason
$labGroups = @(
    'Finance-App', 'VPN-Users', 'App-Admins', 'Finance-Team',
    'Enclave-HPC-Users', 'Enclave-Storage-RW', 'Enclave-VPN-Access',
    'Enclave-Admins', 'Enclave-GradStudents',
    'SDC-HPC-Users', 'SDC-Storage-RW', 'SDC-VPN-Access',
    'SDC-Admins', 'SDC-GradStudents'
)

# --------------------------------------------------------------- inventory
$targets = @()
foreach ($name in $OuName) {
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
    if ($ou) { $targets += $ou }
}

$strayGroups = @()
foreach ($g in $labGroups) {
    $found = Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue
    foreach ($f in $found) {
        $inTarget = $false
        foreach ($t in $targets) {
            if ($f.DistinguishedName -like "*,$($t.DistinguishedName)") { $inTarget = $true }
        }
        if (-not $inTarget) { $strayGroups += $f }
    }
}

if (-not $targets -and -not $strayGroups) {
    Write-Host "[=] Nothing to remove - no demo OU or lab groups found in $($domain.DNSRoot)."
    return
}

Write-Host ""
Write-Host "The following objects will be PERMANENTLY DELETED from $($domain.DNSRoot):"
Write-Host ""
$totalUsers = 0; $totalGroups = 0
foreach ($t in $targets) {
    $users  = @(Get-ADUser  -SearchBase $t.DistinguishedName -Filter * -ErrorAction SilentlyContinue)
    $groups = @(Get-ADGroup -SearchBase $t.DistinguishedName -Filter * -ErrorAction SilentlyContinue)
    $totalUsers += $users.Count; $totalGroups += $groups.Count
    Write-Host ("  OU: {0}" -f $t.DistinguishedName) -ForegroundColor Yellow
    Write-Host ("      {0} user(s): {1}" -f $users.Count, (($users | ForEach-Object { $_.SamAccountName }) -join ', '))
    Write-Host ("      {0} group(s): {1}" -f $groups.Count, (($groups | ForEach-Object { $_.Name }) -join ', '))
}
foreach ($g in $strayGroups) {
    $totalGroups++
    Write-Host ("  Group outside the OU: {0}" -f $g.DistinguishedName) -ForegroundColor Yellow
}
Write-Host ""
Write-Host ("  Total: {0} user(s), {1} group(s), {2} OU(s)" -f $totalUsers, $totalGroups, @($targets).Count)
Write-Host ""

if (-not $Force) {
    $answer = Read-Host "Type DELETE to confirm (anything else cancels)"
    if ($answer -cne 'DELETE') {
        Write-Host "[=] Cancelled. Nothing was removed."
        return
    }
}

# --------------------------------------------------------------- teardown
foreach ($t in $targets) {
    # clear accidental-deletion protection on the OU and everything under it
    Get-ADObject -SearchBase $t.DistinguishedName -Filter * `
                 -Properties ProtectedFromAccidentalDeletion |
        Where-Object { $_.ProtectedFromAccidentalDeletion } |
        Set-ADObject -ProtectedFromAccidentalDeletion $false

    Remove-ADOrganizationalUnit -Identity $t.DistinguishedName -Recursive -Confirm:$false
    Write-Host ("[+] Removed OU and all contents: {0}" -f $t.DistinguishedName)
}

foreach ($g in $strayGroups) {
    Remove-ADGroup -Identity $g.DistinguishedName -Confirm:$false
    Write-Host ("[+] Removed stray group: {0}" -f $g.Name)
}

Write-Host ""
Write-Host "=== Teardown complete ==="
Write-Host "Verify in ADUC (dsa.msc) that the demo OU is gone, then seed a fresh lab:"
Write-Host "    .\adcert.ps1 lab seed"
