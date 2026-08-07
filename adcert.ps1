<#
.SYNOPSIS
  adcert - humane periodic user access reviews for Active Directory.

.DESCRIPTION
  One command, one folder. Run a verb:

    preflight   check the config and directory for data-quality problems
                that would silently degrade a campaign
    new         collect from AD and write a campaign folder of reviewer pages
    compile     turn returned decision files into audit evidence
    verify      independently re-check the evidence integrity chain
    confirm     re-query AD and record whether revocations actually happened
    lab seed    build a fictional demo company on a throwaway lab domain
    lab remove  tear that demo lab down again

  Run with no arguments for the verb list.

.EXAMPLE
  .\adcert.ps1 preflight -Config config\groups.json

.EXAMPLE
  .\adcert.ps1 new -Config config\groups.json -OutDir C:\adcert\UAR-2026-Q3

.EXAMPLE
  .\adcert.ps1 compile C:\adcert\UAR-2026-Q3

.EXAMPLE
  .\adcert.ps1 confirm C:\adcert\UAR-2026-Q3
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Verb = '',
    [Parameter(Position = 1)][string]$Target = '',
    [string]$Config = '',
    [string]$OutDir = '',
    [string]$Campaign = '',
    [string]$PriorSnapshot = '',
    [string]$InputSnapshot = '',
    [switch]$Strict,
    [switch]$SkipAD,
    [switch]$Force,
    [string]$From = '',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Import-Module (Join-Path $root 'lib\Adcert.psm1') -Force

$DefaultConfig = Join-Path $root 'config\groups.json'

function Write-AdcertBanner {
    Write-Host ""
    Write-Host "  adcert - periodic user access reviews for Active Directory" -ForegroundColor White
    Write-Host ""
    Write-Host "  USAGE   .\adcert.ps1 <verb> [options]"
    Write-Host ""
    Write-Host "  VERBS"
    Write-Host "    preflight   Check config and directory data quality before a campaign."
    Write-Host "                -Config <path>  [-SkipAD]"
    Write-Host "    new         Collect from AD and build the reviewer pages."
    Write-Host "                -Config <path> -OutDir <folder> [-Campaign <name>]"
    Write-Host "                [-PriorSnapshot <snapshot.json>] [-InputSnapshot <snapshot.json>]"
    Write-Host "    send        Email each reviewer their own review page."
    Write-Host "                <campaign folder> [-DryRun]"
    Write-Host "    collect     Rescue exported decision files from Downloads and file"
    Write-Host "                them under the right reviewer. <campaign folder> [-From <dir>] [-DryRun]"
    Write-Host "    compile     Turn returned decision files into audit evidence."
    Write-Host "                <campaign folder> [-Strict]"
    Write-Host "    verify      Re-check the evidence integrity chain independently."
    Write-Host "                <campaign folder>"
    Write-Host "    confirm     Re-query AD: did the revocations actually happen?"
    Write-Host "                <campaign folder>"
    Write-Host "    lab seed    Build the fictional demo company (lab domain only)."
    Write-Host "    lab remove  Tear the demo lab down again."
    Write-Host ""
    Write-Host "  A typical cycle:"
    Write-Host "    .\adcert.ps1 preflight -Config config\groups.json"
    Write-Host "    .\adcert.ps1 new       -Config config\groups.json -OutDir C:\adcert\UAR-Q3"
    Write-Host "    .\adcert.ps1 send      C:\adcert\UAR-Q3 -DryRun"
    Write-Host "    ... reviewers open review_*.html, decide, Export back into their folder ..."
    Write-Host "    .\adcert.ps1 collect   C:\adcert\UAR-Q3"
    Write-Host "    .\adcert.ps1 compile   C:\adcert\UAR-Q3"
    Write-Host "    ... run evidence\revocation_worklist.ps1 ..."
    Write-Host "    .\adcert.ps1 confirm   C:\adcert\UAR-Q3"
    Write-Host ""
}

function Resolve-ConfigPath {
    param([string]$Path)
    if (-not $Path) { $Path = $DefaultConfig }
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $candidate = Join-Path $root $Path
        if (Test-Path $candidate) { return $candidate }
    }
    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path (looked relative to $root as well)"
    }
    $Path
}

function Require-Campaign {
    param([string]$Path)
    if (-not $Path) {
        throw "This verb needs a campaign folder. Example: .\adcert.ps1 $Verb C:\adcert\UAR-Q3"
    }
    if (-not (Test-Path $Path)) { throw "Campaign folder not found: $Path" }
    $Path
}

switch ($Verb.ToLower()) {

    # ------------------------------------------------------------- preflight
    'preflight' {
        $cfgPath = Resolve-ConfigPath $Config
        Write-Host "[=] Preflight against $cfgPath"
        $cfg = Get-AdcertConfig -Path $cfgPath
        $r = Invoke-AdcertPreflight -Config $cfg -SkipAD:$SkipAD

        foreach ($i in $r.Info)     { Write-Host "[i] $i" }
        foreach ($w in $r.Warnings) { Write-Host "[!] $w" -ForegroundColor Yellow }
        foreach ($e in $r.Errors)   { Write-Host "[x] $e" -ForegroundColor Red }

        Write-Host ""
        if ($r.Errors.Count) {
            Write-Host "[x] $($r.Errors.Count) error(s), $($r.Warnings.Count) warning(s). Fix the errors before running 'new'." -ForegroundColor Red
            exit 2
        } elseif ($r.Warnings.Count) {
            Write-Host "[!] $($r.Warnings.Count) warning(s). The campaign will run, but review the notes above first." -ForegroundColor Yellow
            Write-Host "    Next:  .\adcert.ps1 new -Config $cfgPath -OutDir <folder>" -ForegroundColor Cyan
            exit 1
        } else {
            Write-Host "[+] No problems found." -ForegroundColor Green
            Write-Host "    Next:  .\adcert.ps1 new -Config $cfgPath -OutDir <folder>" -ForegroundColor Cyan
            exit 0
        }
    }

    # ------------------------------------------------------------------- new
    'new' {
        $cfgPath = Resolve-ConfigPath $Config
        if (-not $OutDir) {
            if ($Target) { $OutDir = $Target }
            else { throw "'new' needs -OutDir. Example: .\adcert.ps1 new -Config config\groups.json -OutDir C:\adcert\UAR-Q3" }
        }
        $cfg = Get-AdcertConfig -Path $cfgPath
        $resolved = Invoke-AdcertCampaign -Config $cfg -OutDir $OutDir -Campaign $Campaign `
                                          -PriorSnapshot $PriorSnapshot -InputSnapshot $InputSnapshot
        Write-Host ""
        Write-Host "[+] Campaign ready: $resolved"
        Write-Host ""
        Write-Host "    NEXT STEPS"
        Write-Host "    1. Each reviewer opens their review_<name>_*.html (any browser)."
        Write-Host "    2. They decide every row, click 'Export decisions', and save the"
        Write-Host "       file back into this campaign folder (any subfolder is fine)."
        Write-Host "    3. When decision files are in, run:"
        Write-Host ""
        Write-Host "       .\adcert.ps1 compile `"$resolved`"" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    Re-run step 3 any time as more reviewers finish - it reports who"
        Write-Host "    is still outstanding."
        exit 0
    }

    # ------------------------------------------------------------------ send
    'send' {
        $dir = Require-Campaign $Target
        $cfgPath = Resolve-ConfigPath $Config
        $cfg = Get-AdcertConfig -Path $cfgPath
        if (-not $cfg.Contains('smtp') -or $null -eq $cfg['smtp']) {
            Write-Host "[x] No 'smtp' block in $cfgPath." -ForegroundColor Red
            Write-Host "    Add one, for example:"
            Write-Host '      "smtp": { "server": "smtp.example.com", "port": 25,'
            Write-Host '                "from": "access-reviews@example.com", "use_ssl": false,'
            Write-Host '                "subject": "Access review due: {campaign}" }'
            exit 2
        }
        Import-Module ActiveDirectory -ErrorAction Stop
        $results = Send-AdcertReviews -CampaignDir $dir -Smtp $cfg['smtp'] -DryRun:$DryRun
        $sent = 0; $failed = 0
        foreach ($r in $results) {
            switch ($r.Status) {
                'sent'       { Write-Host ("[+] {0,-14} -> {1}  {2}" -f $r.Reviewer, $r.Address, $r.Detail) -ForegroundColor Green; $sent++ }
                'would send' { Write-Host ("[=] {0,-14} -> {1}  {2}" -f $r.Reviewer, $r.Address, $r.Detail) -ForegroundColor Cyan; $sent++ }
                'skipped'    { Write-Host ("[!] {0,-14} skipped: {1}" -f $r.Reviewer, $r.Detail) -ForegroundColor Yellow }
                default      { Write-Host ("[x] {0,-14} {1}" -f $r.Reviewer, $r.Detail) -ForegroundColor Red; $failed++ }
            }
        }
        Write-Host ""
        if ($DryRun) {
            Write-Host "[=] Dry run: nothing was sent. Re-run without -DryRun to deliver." -ForegroundColor Cyan
        } else {
            Write-Host "[+] $sent message(s) sent."
        }
        if ($failed) { exit 1 }
        exit 0
    }

    # --------------------------------------------------------------- collect
    'collect' {
        $dir = Require-Campaign $Target
        $results = Invoke-AdcertCollect -CampaignDir $dir -From $From -DryRun:$DryRun
        if (-not @($results).Count) {
            Write-Host "[=] No decisions_*.json files found in $(if ($From) { $From } else { 'Downloads, Desktop, or Documents' })."
            Write-Host "    Nothing to collect - reviewers may have saved directly into the campaign folder already."
            exit 0
        }
        $moved = 0
        foreach ($r in $results) {
            switch ($r.Action) {
                'moved'      { Write-Host ("[+] {0,-14} {1}" -f $r.Reviewer, $r.Reason) -ForegroundColor Green; $moved++ }
                'would move' { Write-Host ("[=] {0,-14} would file to {1}" -f $r.Reviewer, $r.Reason) -ForegroundColor Cyan; $moved++ }
                default      { Write-Host ("[!] {0}: {1}" -f (Split-Path $r.File -Leaf), $r.Reason) -ForegroundColor Yellow }
            }
        }
        Write-Host ""
        if ($DryRun) {
            Write-Host "[=] Dry run: nothing was moved." -ForegroundColor Cyan
        } else {
            Write-Host "[+] $moved decision file(s) filed into the campaign."
            if ($moved) { Write-Host "    Next:  .\adcert.ps1 compile `"$dir`"" -ForegroundColor Cyan }
        }
        exit 0
    }

    # --------------------------------------------------------------- compile
    'compile' {
        $dir = Require-Campaign $Target
        $r = Invoke-AdcertCompile -CampaignDir $dir -Strict:$Strict
        if (-not $r.Outstanding -or $r.Outstanding.Count -eq @((Get-AdcertCampaignContext -CampaignDir $dir).Manifest['reviewers']).Count) {
            Write-Host "    Tip: if reviewers exported to their Downloads folder, run" -ForegroundColor Yellow
            Write-Host "         .\adcert.ps1 collect `"$dir`"  to file those in first." -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "[+] Evidence written to $($r.EvidenceDir)"
        Write-Host "    Open evidence_report.html for the campaign summary."
        if ($r.Outstanding.Count) {
            Write-Host "[!] Still waiting on: $($r.Outstanding -join ', ')" -ForegroundColor Yellow
            Write-Host "    Run the same command again once their decision files arrive."
        } else {
            Write-Host "[+] All reviewers complete." -ForegroundColor Green
            Write-Host ""
            Write-Host "    NEXT STEPS"
            Write-Host "    1. Inspect $($r.EvidenceDir)\revocation_worklist.ps1, then run it."
            Write-Host "       It starts in -WhatIf mode; set `$Commit = `$true to apply."
            Write-Host "    2. Confirm the removals actually landed:"
            Write-Host ""
            Write-Host "       .\adcert.ps1 confirm `"$dir`"" -ForegroundColor Cyan
        }
        if ($r.StrictFail) { exit 3 }
        exit 0
    }

    # ---------------------------------------------------------------- verify
    'verify' {
        $dir = Require-Campaign $Target
        $results = Test-AdcertChain -CampaignDir $dir
        $failed = 0
        foreach ($r in $results) {
            if ($r.ok) {
                Write-Host ("[+] {0,-34} {1}" -f $r.link, $r.detail) -ForegroundColor Green
            } else {
                $failed++
                Write-Host ("[x] {0,-34} {1}" -f $r.link, $r.detail) -ForegroundColor Red
            }
        }
        Write-Host ""
        if ($failed) {
            Write-Host "[x] $failed of $(@($results).Count) link(s) FAILED - an artifact was modified after the fact." -ForegroundColor Red
            exit 2
        }
        Write-Host "[+] All $(@($results).Count) link(s) verified. The evidence chain is intact." -ForegroundColor Green
        exit 0
    }

    # --------------------------------------------------------------- confirm
    'confirm' {
        $dir = Require-Campaign $Target
        $results = Invoke-AdcertConfirm -CampaignDir $dir
        if (-not @($results).Count) {
            Write-Host "[=] No revocations were recorded in this campaign - nothing to confirm."
            exit 0
        }
        $applied = 0; $outstanding = 0
        foreach ($r in $results) {
            switch ($r['status']) {
                'removed'       { Write-Host ("[+] {0,-14} removed from {1}" -f $r['sam'], $r['group']) -ForegroundColor Green; $applied++ }
                'user_missing'  { Write-Host ("[+] {0,-14} account no longer exists ({1})" -f $r['sam'], $r['group']) -ForegroundColor Green; $applied++ }
                'group_missing' { Write-Host ("[+] {0,-14} group {1} no longer exists" -f $r['sam'], $r['group']) -ForegroundColor Green; $applied++ }
                default         { Write-Host ("[x] {0,-14} STILL a member of {1}" -f $r['sam'], $r['group']) -ForegroundColor Red; $outstanding++ }
            }
        }
        Write-Host ""
        Write-Host "[+] $applied of $(@($results).Count) revocation(s) confirmed applied."
        $evidence = (Get-AdcertCampaignContext -CampaignDir $dir).EvidenceDir
        Write-Host "    Report: $evidence\remediation_report.html"
        if ($outstanding) {
            Write-Host "[!] $outstanding revocation(s) have not taken effect yet. Run the" -ForegroundColor Yellow
            Write-Host "    revocation worklist, then run this verb again." -ForegroundColor Yellow
            exit 1
        }
        Write-Host "[+] Every reviewer decision has taken effect in the directory." -ForegroundColor Green
        exit 0
    }

    # ------------------------------------------------------------------- lab
    'lab' {
        switch ($Target.ToLower()) {
            'seed'   { & (Join-Path $root 'lib\Seed-DemoLab.ps1'); exit $LASTEXITCODE }
            'remove' {
                if ($Force) { & (Join-Path $root 'lib\Remove-LabAD.ps1') -Force }
                else        { & (Join-Path $root 'lib\Remove-LabAD.ps1') }
                exit $LASTEXITCODE
            }
            default  {
                Write-Host "[x] 'lab' needs 'seed' or 'remove'." -ForegroundColor Red
                Write-Host "    .\adcert.ps1 lab seed"
                Write-Host "    .\adcert.ps1 lab remove"
                exit 2
            }
        }
    }

    # ------------------------------------------------------------------ help
    { $_ -in @('', 'help', '-h', '--help', '/?') } {
        Write-AdcertBanner
        exit 0
    }

    default {
        Write-Host "[x] Unknown verb: '$Verb'" -ForegroundColor Red
        Write-AdcertBanner
        exit 2
    }
}
