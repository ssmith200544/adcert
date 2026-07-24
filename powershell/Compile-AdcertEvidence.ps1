<#
.SYNOPSIS
  adcert - compile returned reviewer decisions into audit evidence.

.DESCRIPTION
  Point it at the campaign folder. That's it.

  It finds decisions_*.json files anywhere in the campaign folder (top level
  or any subfolder, so a 'returned' subfolder works too), validates each
  against the campaign (hash chain, coverage, justifications), and writes:

    <CampaignDir>\evidence\attestations.json         hash-chained attestations
    <CampaignDir>\evidence\evidence_report.html      assessor-facing summary
    <CampaignDir>\evidence\revocation_worklist.ps1   -WhatIf-guarded revokes

  Console output lists validation problems and reviewers still outstanding.
  Safe to re-run any time as more decision files arrive.

.EXAMPLE
  .\Compile-AdcertEvidence.ps1 C:\adcert\UAR-2026-Q3

.EXAMPLE
  # -Strict excludes decision files with validation problems and exits 3
  .\Compile-AdcertEvidence.ps1 C:\adcert\UAR-2026-Q3 -Strict
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$CampaignDir,
    [string]$DecisionsDir = "",   # optional override; default: scan CampaignDir
    [string]$OutDir = "",         # optional override; default: CampaignDir\evidence
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Adcert.psm1') -Force

$manifestPath = Join-Path $CampaignDir 'campaign_manifest.json'
$snapshotPath = Join-Path $CampaignDir 'snapshot.json'
if (-not (Test-Path $manifestPath)) {
    Write-Error "No campaign_manifest.json in '$CampaignDir' - is this a campaign folder created by New-AdcertCampaign.ps1?"
    exit 2
}
$manifest = ConvertTo-Hashtable (Get-Content -Raw -Path $manifestPath | ConvertFrom-Json)

$snapHash = Get-Sha256OfFile $snapshotPath
if ($manifest['snapshot_sha256'] -ne $snapHash) {
    Write-Error "Snapshot in $CampaignDir does not match the manifest hash - wrong or modified file."
    exit 2
}

if (-not $OutDir) { $OutDir = Join-Path $CampaignDir 'evidence' }

# expected (group||sam) pairs per reviewer, from the review packages
$expected = @{}
foreach ($pj in (Get-ChildItem -Path $CampaignDir -Filter 'review_*.json')) {
    $pkg = ConvertTo-Hashtable (Get-Content -Raw -Path $pj.FullName | ConvertFrom-Json)
    $pairs = @{}
    foreach ($e in $pkg['entries']) { $pairs[$e['group'] + '||' + $e['sam']] = $true }
    $expected[$pkg['reviewer']] = $pairs
}

# find decision files: override dir if given, else campaign dir recursively
# (excluding the evidence output folder so re-runs don't re-read anything there)
if ($DecisionsDir) {
    $decisionFiles = @(Get-ChildItem -Path $DecisionsDir -Filter 'decisions_*.json' -Recurse)
} else {
    $decisionFiles = @(Get-ChildItem -Path $CampaignDir -Filter 'decisions_*.json' -Recurse |
                       Where-Object { $_.FullName -notlike (Join-Path $OutDir '*') })
}
if (-not $decisionFiles.Count) {
    Write-Host "[!] No decisions_*.json files found in $CampaignDir yet." -ForegroundColor Yellow
    Write-Host "    Reviewers export them from their review_*.html page; save or copy"
    Write-Host "    them anywhere inside the campaign folder, then re-run this script."
}

$attestations = New-Object System.Collections.ArrayList
$strictFail = $false
foreach ($dfile in ($decisionFiles | Sort-Object Name)) {
    $df = ConvertTo-Hashtable (Get-Content -Raw -Path $dfile.FullName | ConvertFrom-Json)
    $pairs = $expected[$df['reviewer']]
    if ($null -eq $pairs) { $pairs = @{} }
    $problems = Test-DecisionFile -Decision $df -SnapshotSha256 $snapHash -ExpectedPairs $pairs
    if (@($problems).Count) {
        Write-Host "[!] $($dfile.Name):" -ForegroundColor Yellow
        foreach ($p in $problems) { Write-Host "      - $p" -ForegroundColor Yellow }
        if ($Strict) { $strictFail = $true; continue }
    }
    $controls = @()
    if ($manifest.Contains('compliance') -and $null -ne $manifest['compliance'] -and
        $manifest['compliance'].Contains('controls')) {
        $controls = @($manifest['compliance']['controls'])
    }
    [void]$attestations.Add((New-Attestation -Decision $df -SnapshotSha256 $snapHash -Controls $controls))
    Write-Host "[+] Attested: $($df['reviewer']) ($(@($df['decisions']).Count) decisions)"
}

$compliance = $null
if ($manifest.Contains('compliance')) { $compliance = $manifest['compliance'] }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
ConvertTo-Json @($attestations) -Depth 10 |
    Set-Content -Path (Join-Path $OutDir 'attestations.json') -Encoding UTF8
New-RevocationScript -Attestations @($attestations) |
    Set-Content -Path (Join-Path $OutDir 'revocation_worklist.ps1') -Encoding UTF8
New-EvidenceReport -Campaign $manifest['campaign'] -SnapshotSha256 $snapHash `
    -Attestations @($attestations) -ExpectedReviewers @($manifest['reviewers']) `
    -Compliance $compliance |
    Set-Content -Path (Join-Path $OutDir 'evidence_report.html') -Encoding UTF8

$done = @{}
foreach ($a in $attestations) { $done[$a['reviewer']] = $true }
$outstanding = @($manifest['reviewers'] | Where-Object { -not $done.ContainsKey($_) })

Write-Host ""
Write-Host "[+] Evidence written to $OutDir"
Write-Host "    Open evidence_report.html for the campaign summary."
if ($outstanding.Count) {
    Write-Host "[!] Still waiting on: $($outstanding -join ', ')" -ForegroundColor Yellow
    Write-Host "    Re-run this same command after their decision files arrive."
} else {
    Write-Host "[+] All reviewers complete. Execute revocations (review first!):"
    Write-Host "    Inspect $OutDir\revocation_worklist.ps1, then run it (starts in -WhatIf mode)."
}
if ($strictFail) { exit 3 }
