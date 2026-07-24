<#
.SYNOPSIS
  adcert - one command from Active Directory to reviewer HTML pages.

.DESCRIPTION
  Collects membership for the in-scope groups defined in the config, scores
  and routes every grant, and writes a complete campaign folder:

    <OutDir>\
      snapshot.json            raw collected data (SHA-256 anchors the chain)
      campaign_manifest.json   campaign metadata + reviewer list
      review_<sam>_<id>.html   one self-contained page per reviewer
      review_<sam>_<id>.json   machine-readable copy of each package

  Distribute the HTML files to reviewers (email, share, USB). Reviewers open
  them in any browser - no server, no install - and export a decisions file.
  Feed returned decision files to Compile-AdcertEvidence.ps1.

  Requires RSAT ActiveDirectory module for live collection. With -InputSnapshot
  it runs fully offline against a previously collected snapshot (no AD needed).

.EXAMPLE
  .\New-AdcertCampaign.ps1 -Config ..\config\groups.json -OutDir C:\adcert\UAR-2026-Q3

.EXAMPLE
  .\New-AdcertCampaign.ps1 -Config ..\config\groups.json -OutDir .\Q3 `
      -PriorSnapshot C:\adcert\UAR-2026-Q2\snapshot.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Config,
    [Parameter(Mandatory)][string]$OutDir,
    [string]$Campaign = "",
    [string]$PriorSnapshot = "",
    [string]$InputSnapshot = ""   # skip AD collection; use an existing snapshot
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Adcert.psm1') -Force

$cfg = ConvertTo-Hashtable (Get-Content -Raw -Path $Config | ConvertFrom-Json)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$snapshotPath = Join-Path $OutDir 'snapshot.json'

# ---------------------------------------------------------------- Stage 1
if ($InputSnapshot) {
    Copy-Item -Path $InputSnapshot -Destination $snapshotPath -Force
    Write-Host "[=] Using existing snapshot: $InputSnapshot"
} else {
    Import-Module ActiveDirectory -ErrorAction Stop

    function Convert-FileTimeIso {
        param($ft)
        if (-not $ft -or $ft -eq 0 -or $ft -eq 0x7FFFFFFFFFFFFFFF) { return $null }
        [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-ddTHH:mm:ss+0000")
    }

    $groups = @()
    foreach ($entry in $cfg['groups']) {
        $gName = $entry['name']
        try { $adGroup = Get-ADGroup -Identity $gName -Properties Description }
        catch { Write-Warning "Group not found, skipping: $gName"; continue }

        $members = @()
        # -Recursive resolves nested groups so nesting can't hide a grant.
        foreach ($u in (Get-ADGroupMember -Identity $gName -Recursive |
                        Where-Object objectClass -eq 'user')) {
            $user = Get-ADUser -Identity $u.SamAccountName -Properties `
                DisplayName, Title, Department, Manager, Enabled, `
                lastLogonTimestamp, lastLogon, pwdLastSet, whenCreated, accountExpires

            # Take the most recent of the replicated (lastLogonTimestamp) and
            # per-DC (lastLogon) attributes. On a single-DC domain the per-DC
            # value updates immediately, so labs and small sites see fresh
            # activity instead of the up-to-14-day replication lag.
            $llt = 0; $ll = 0
            if ($user.lastLogonTimestamp) { $llt = [long]$user.lastLogonTimestamp }
            if ($user.lastLogon)          { $ll  = [long]$user.lastLogon }
            $best = [math]::Max($llt, $ll)

            $managerSam = ""
            if ($user.Manager) {
                try { $managerSam = (Get-ADUser -Identity $user.Manager).SamAccountName }
                catch { $managerSam = "" }
            }

            $members += [ordered]@{
                sam             = $user.SamAccountName
                display_name    = "$($user.DisplayName)"
                title           = "$($user.Title)"
                department      = "$($user.Department)"
                manager_sam     = $managerSam
                enabled         = [bool]$user.Enabled
                last_logon      = Convert-FileTimeIso $best
                pwd_last_set    = Convert-FileTimeIso $user.pwdLastSet
                when_created    = $user.whenCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+0000")
                account_expires = Convert-FileTimeIso $user.accountExpires
            }
        }

        $groups += [ordered]@{
            name           = $gName
            ad_description = "$($adGroup.Description)"
            plain_language = "$($entry['plain_language'])"
            members        = @($members | Sort-Object { $_['sam'] })
        }
        Write-Host "[+] Collected $gName ($(@($members).Count) members)"
    }

    $snapshot = [ordered]@{
        generated_at = Get-UtcNowIso
        source       = "AD:$((Get-ADDomain).DNSRoot)"
        groups       = $groups
    }
    ConvertTo-Json $snapshot -Depth 10 |
        Set-Content -Path $snapshotPath -Encoding UTF8
}

$snapHash = Get-Sha256OfFile $snapshotPath
Write-Host "[+] Snapshot: $snapshotPath"
Write-Host "    SHA-256: $snapHash"

# ---------------------------------------------------------------- Stage 2
$snap = ConvertTo-Hashtable (Get-Content -Raw -Path $snapshotPath | ConvertFrom-Json)

$prior = $null
if ($PriorSnapshot) {
    $prior = ConvertTo-Hashtable (Get-Content -Raw -Path $PriorSnapshot | ConvertFrom-Json)
    Write-Host "[+] Diffing against prior snapshot: $PriorSnapshot"
}

$packages = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 $snapHash `
                                 -Config $cfg -PriorSnapshot $prior -Campaign $Campaign

$manifest = [ordered]@{
    campaign        = if (@($packages).Count) { $packages[0]['campaign'] } else { $Campaign }
    snapshot_sha256 = $snapHash
    reviewers       = @()
}
# carry the compliance framing (if the config supplies one) into the manifest
# so the evidence report is mapped to whatever framework this campaign serves
if ($cfg.Contains('compliance') -and $null -ne $cfg['compliance']) {
    $manifest['compliance'] = $cfg['compliance']
}
foreach ($pkg in $packages) {
    $base = Join-Path $OutDir ("review_{0}_{1}" -f $pkg['reviewer'], $pkg['review_id'])
    ConvertTo-Json $pkg -Depth 10 | Set-Content -Path "$base.json" -Encoding UTF8
    New-ReviewHtml -Package $pkg | Set-Content -Path "$base.html" -Encoding UTF8
    $manifest['reviewers'] += $pkg['reviewer']
    $tag = ""
    if ($pkg['reviewer'] -eq '_unrouted') { $tag = "  [UNROUTED - assign manually]" }
    Write-Host ("[+] {0,-16} {1,3} entries -> {2}.html{3}" -f `
        $pkg['reviewer'], @($pkg['entries']).Count, (Split-Path $base -Leaf), $tag)
}
ConvertTo-Json $manifest -Depth 5 |
    Set-Content -Path (Join-Path $OutDir 'campaign_manifest.json') -Encoding UTF8

$resolved = (Resolve-Path $OutDir).Path
Write-Host ""
Write-Host "[+] Campaign ready: $resolved"
Write-Host ""
Write-Host "    NEXT STEPS"
Write-Host "    1. Have each reviewer open their review_<name>_*.html (any browser)."
Write-Host "    2. They decide every row, click 'Export decisions', and save the file"
Write-Host "       into this same campaign folder (any subfolder is fine)."
Write-Host "    3. When decision files are in, run:"
Write-Host ""
Write-Host "       .\Compile-AdcertEvidence.ps1 `"$resolved`"" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Evidence lands in $resolved\evidence. Re-run step 3 any time"
Write-Host "    as more reviewers finish - it will tell you who is still outstanding."
