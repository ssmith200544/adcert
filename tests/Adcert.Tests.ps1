# Adcert.Tests.ps1 - Pester 5 tests for the adcert PowerShell module.
# Run on the VM (or any Windows box):
#   Install-Module Pester -Force -SkipPublisherCheck   # once
#   Invoke-Pester .\powershell\tests\Adcert.Tests.ps1
# No AD required - everything here exercises pure functions.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\lib\Adcert.psm1') -Force

    function New-TestMember {
        param([hashtable]$Overrides = @{})
        $m = @{
            sam = 'jdoe'; display_name = 'J Doe'; title = 'RA'; department = 'ECE'
            manager_sam = 'boss'; enabled = $true
            last_logon = (Get-Date).ToUniversalTime().AddDays(-5).ToString("yyyy-MM-ddTHH:mm:ss+0000")
            pwd_last_set = $null; when_created = $null; account_expires = $null
        }
        foreach ($k in $Overrides.Keys) { $m[$k] = $Overrides[$k] }
        $m
    }

    function New-TestSnapshot {
        @{
            generated_at = Get-UtcNowIso; source = 'test'
            groups = @(
                @{ name = 'G1'; ad_description = 'd1'; plain_language = 'Plain G1'
                   members = @(
                       (New-TestMember),
                       (New-TestMember @{ sam = 'asmith'; display_name = 'A Smith'; manager_sam = 'boss' }),
                       (New-TestMember @{ sam = 'boss'; display_name = 'The Boss'; manager_sam = '' })
                   ) },
                @{ name = 'G2-Admins'; ad_description = 'priv'; plain_language = 'Privileged'
                   members = @(
                       (New-TestMember @{ sam = 'stale'; enabled = $false; manager_sam = 'boss' })
                   ) }
            )
        }
    }
}

Describe 'Get-EntryRisk' {
    It 'scores an active recent user as zero risk' {
        $r = Get-EntryRisk -Member (New-TestMember) -GroupName 'G'
        $r.Risk | Should -Be 0
        $r.Flags | Should -BeNullOrEmpty
    }
    It 'flags disabled accounts heavily' {
        $r = Get-EntryRisk -Member (New-TestMember @{ enabled = $false }) -GroupName 'G'
        $r.Risk | Should -BeGreaterOrEqual 50
        ($r.Flags -join ' ') | Should -Match 'DISABLED'
    }
    It 'flags never-logged-on accounts' {
        $r = Get-EntryRisk -Member (New-TestMember @{ last_logon = $null }) -GroupName 'G'
        $r.Risk | Should -BeGreaterOrEqual 30
        ($r.Flags -join ' ') | Should -Match 'never logged on'
    }
    It 'scales dormancy risk with days' {
        $d95 = (Get-Date).ToUniversalTime().AddDays(-95).ToString("yyyy-MM-ddTHH:mm:ss+0000")
        $d300 = (Get-Date).ToUniversalTime().AddDays(-300).ToString("yyyy-MM-ddTHH:mm:ss+0000")
        $r95 = Get-EntryRisk -Member (New-TestMember @{ last_logon = $d95 }) -GroupName 'G'
        $r300 = Get-EntryRisk -Member (New-TestMember @{ last_logon = $d300 }) -GroupName 'G'
        $r300.Risk | Should -BeGreaterThan $r95.Risk
        $r95.Risk | Should -BeGreaterThan 0
    }
    It 'does not flag activity under the 90-day threshold' {
        $d89 = (Get-Date).ToUniversalTime().AddDays(-89).ToString("yyyy-MM-ddTHH:mm:ss+0000")
        $r = Get-EntryRisk -Member (New-TestMember @{ last_logon = $d89 }) -GroupName 'G'
        ($r.Flags -join ' ') | Should -Not -Match 'Dormant'
    }
    It 'multiplies risk for privileged groups' {
        $d120 = (Get-Date).ToUniversalTime().AddDays(-120).ToString("yyyy-MM-ddTHH:mm:ss+0000")
        $m = New-TestMember @{ last_logon = $d120 }
        $plain = Get-EntryRisk -Member $m -GroupName 'G'
        $priv = Get-EntryRisk -Member $m -GroupName 'G' -PrivilegedGroups @('G')
        $priv.Risk | Should -BeGreaterThan $plain.Risk
        ($priv.Flags -join ' ') | Should -Match 'Privileged'
    }
    It 'flags passed and imminent account expiration' {
        $past = (Get-Date).ToUniversalTime().AddDays(-3).ToString("yyyy-MM-ddTHH:mm:ss+0000")
        $soon = (Get-Date).ToUniversalTime().AddDays(10).ToString("yyyy-MM-ddTHH:mm:ss+0000")
        (Get-EntryRisk -Member (New-TestMember @{ account_expires = $past }) -GroupName 'G').Flags -join ' ' |
            Should -Match 'passed'
        (Get-EntryRisk -Member (New-TestMember @{ account_expires = $soon }) -GroupName 'G').Flags -join ' ' |
            Should -Match 'expires in'
    }
}

Describe 'ConvertTo-CanonicalJson' {
    It 'produces identical output regardless of key order' {
        $a = [ordered]@{ b = 1; a = 'x'; c = @(1, 2) }
        $b = [ordered]@{ c = @(1, 2); a = 'x'; b = 1 }
        (ConvertTo-CanonicalJson $a) | Should -Be (ConvertTo-CanonicalJson $b)
    }
    It 'handles null, bool, and nesting' {
        ConvertTo-CanonicalJson $null | Should -Be 'null'
        ConvertTo-CanonicalJson $true | Should -Be 'true'
        ConvertTo-CanonicalJson @{ x = @{ y = $false } } | Should -Be '{"x":{"y":false}}'
    }
}

Describe 'Build-ReviewPackages' {
    It 'routes by group mapping first, manager second, _unrouted last' {
        $snap = New-TestSnapshot
        $cfg = @{ reviewers = @{ 'G2-Admins' = 'secadmin' }; privileged_groups = @('G2-Admins') }
        $pkgs = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 ('a' * 64) -Config $cfg
        $byRev = @{}
        foreach ($p in $pkgs) { $byRev[$p['reviewer']] = $p }
        $byRev.Keys | Should -Contain 'secadmin'    # group mapping
        $byRev.Keys | Should -Contain 'boss'        # manager fallback
        $byRev.Keys | Should -Contain '_unrouted'   # boss has no manager
    }
    It 'never drops an entry' {
        $snap = New-TestSnapshot
        $pkgs = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 ('a' * 64) -Config @{}
        $total = 0
        foreach ($p in $pkgs) { $total += @($p['entries']).Count }
        $total | Should -Be 4
    }
    It 'sorts entries by descending risk' {
        $snap = New-TestSnapshot
        $cfg = @{ reviewers = @{ 'G1' = 'r1'; 'G2-Admins' = 'r1' } }
        $pkgs = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 ('a' * 64) -Config $cfg
        foreach ($p in $pkgs) {
            $risks = @($p['entries'] | ForEach-Object { $_['risk'] })
            $sorted = @($risks | Sort-Object -Descending)
            ($risks -join ',') | Should -Be ($sorted -join ',')
        }
    }
    It 'marks memberships new since the prior snapshot' {
        $prior = New-TestSnapshot
        $current = New-TestSnapshot
        $current['groups'][0]['members'] += (New-TestMember @{ sam = 'brandnew'; display_name = 'Brand New' })
        $pkgs = Build-ReviewPackages -Snapshot $current -SnapshotSha256 ('a' * 64) `
                                     -Config @{} -PriorSnapshot $prior
        $marked = @()
        foreach ($p in $pkgs) {
            $marked += @($p['entries'] | Where-Object { $_['new_since_last_review'] })
        }
        @($marked).Count | Should -Be 1
        $marked[0]['sam'] | Should -Be 'brandnew'
    }
}

Describe 'Test-DecisionFile and New-Attestation' {
    BeforeEach {
        $script:df = @{
            reviewer = 'boss'; review_id = 'abcd1234'
            snapshot_sha256 = ('s' * 64); decided_at = Get-UtcNowIso
            decisions = @(
                @{ group = 'G1'; sam = 'jdoe'; decision = 'retain'; justification = '' },
                @{ group = 'G1'; sam = 'asmith'; decision = 'revoke'; justification = 'left project' }
            )
        }
        $script:expected = @{ 'G1||jdoe' = $true; 'G1||asmith' = $true }
    }
    It 'passes a clean file' {
        Test-DecisionFile -Decision $df -SnapshotSha256 ('s' * 64) -ExpectedPairs $expected |
            Should -BeNullOrEmpty
    }
    It 'catches a broken hash chain' {
        $df['snapshot_sha256'] = 'x' * 64
        (Test-DecisionFile -Decision $df -SnapshotSha256 ('s' * 64) -ExpectedPairs $expected) -join ' ' |
            Should -Match 'integrity chain'
    }
    It 'requires justification on revoke' {
        $df['decisions'][1]['justification'] = ''
        (Test-DecisionFile -Decision $df -SnapshotSha256 ('s' * 64) -ExpectedPairs $expected) -join ' ' |
            Should -Match 'without justification'
    }
    It 'detects missing and out-of-scope decisions' {
        $df['decisions'] = @(@{ group = 'G9'; sam = 'intruder'; decision = 'retain'; justification = '' })
        $problems = (Test-DecisionFile -Decision $df -SnapshotSha256 ('s' * 64) -ExpectedPairs $expected) -join ' '
        $problems | Should -Match 'not part of this reviewer'
        $problems | Should -Match 'no decision recorded'
    }
    It 'produces a tamper-evident attestation hash' {
        $att = New-Attestation -Decision $df -SnapshotSha256 ('s' * 64)
        $recorded = $att['attestation_sha256']
        $att.Remove('attestation_sha256')
        (Get-Sha256OfString (ConvertTo-CanonicalJson $att)) | Should -Be $recorded
        $att['decisions'][1]['decision'] = 'retain'   # tamper
        (Get-Sha256OfString (ConvertTo-CanonicalJson $att)) | Should -Not -Be $recorded
    }
}

Describe 'New-RevocationScript' {
    It 'emits only revokes, WhatIf-guarded' {
        $df = @{
            reviewer = 'boss'; review_id = 'ab'; snapshot_sha256 = ('s' * 64)
            decided_at = Get-UtcNowIso
            decisions = @(
                @{ group = 'G1'; sam = 'jdoe'; decision = 'revoke'; justification = 'gone' },
                @{ group = 'G1'; sam = 'keep'; decision = 'retain'; justification = '' }
            )
        }
        $script = New-RevocationScript -Attestations @((New-Attestation -Decision $df -SnapshotSha256 ('s' * 64)))
        $script | Should -Match "Remove-ADGroupMember -Identity 'G1' -Members 'jdoe'"
        $script | Should -Not -Match "'keep'"
        $script | Should -Match '\$Commit = \$false'
    }
}

Describe 'New-ReviewHtml and New-EvidenceReport' {
    It 'renders a complete review page with the payload embedded' {
        $snap = New-TestSnapshot
        $pkgs = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 ('a' * 64) -Config @{}
        $html = New-ReviewHtml -Package $pkgs[0]
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Not -Match '__PAYLOAD__'
        $html | Should -Not -Match '__REVIEWER__'
        $html | Should -Match 'Export decisions'
    }
    It 'escapes hostile justifications in the evidence report' {
        $df = @{
            reviewer = 'boss'; review_id = 'ab'; snapshot_sha256 = ('s' * 64)
            decided_at = Get-UtcNowIso
            decisions = @(@{ group = 'G1'; sam = 'jdoe'; decision = 'revoke'
                             justification = '<script>alert(1)</script>' })
        }
        $report = New-EvidenceReport -Campaign 'UAR-TEST' -SnapshotSha256 ('s' * 64) `
            -Attestations @((New-Attestation -Decision $df -SnapshotSha256 ('s' * 64))) `
            -ExpectedReviewers @('boss', 'slacker')
        $report | Should -Not -Match '<script>alert'
        $report | Should -Match 'slacker'
        $report | Should -Match 'SOC 2'
    }
}

Describe 'Config plumbing from real JSON' {
    It 'keeps a single-element JSON array as an array' {
        $cfg = ConvertTo-Hashtable ('{"privileged_groups":["X"]}' | ConvertFrom-Json)
        @($cfg['privileged_groups']).Count | Should -Be 1
        @($cfg['privileged_groups'])[0] | Should -Be 'X'
    }
    It 'preserves a multi-element array of objects' {
        $cfg = ConvertTo-Hashtable ('{"groups":[{"name":"A"},{"name":"B"}]}' | ConvertFrom-Json)
        @($cfg['groups']).Count | Should -Be 2
        @($cfg['groups'])[1]['name'] | Should -Be 'B'
    }
    It 'applies privileged_groups that came from a JSON config file' {
        $json = '{"groups":[{"name":"G2-Admins","plain_language":"p"}],' +
                '"reviewers":{"_escalation":"sec"},"privileged_groups":["G2-Admins"]}'
        $cfg = ConvertTo-Hashtable ($json | ConvertFrom-Json)
        $pkgs = Build-ReviewPackages -Snapshot (New-TestSnapshot) `
                    -SnapshotSha256 ('a' * 64) -Config $cfg
        $adminEntries = @()
        foreach ($p in $pkgs) {
            $adminEntries += @($p['entries'] | Where-Object { $_['group'] -eq 'G2-Admins' })
        }
        $adminEntries.Count | Should -BeGreaterThan 0
        ($adminEntries[0]['flags'] -join ' ') | Should -Match 'Privileged group'
    }
}

Describe 'Configurable compliance framing' {
    It 'uses the default framing when none is supplied' {
        $df = @{ reviewer='boss'; review_id='ab'; snapshot_sha256=('s'*64)
                 decided_at=Get-UtcNowIso
                 decisions=@(@{group='G';sam='a';decision='retain';justification=''}) }
        $report = New-EvidenceReport -Campaign 'C' -SnapshotSha256 ('s'*64) `
            -Attestations @((New-Attestation -Decision $df -SnapshotSha256 ('s'*64))) `
            -ExpectedReviewers @('boss')
        $report | Should -Match 'SOC 2'
        $report | Should -Match 'Periodic access review'
    }
    It 'honors a custom compliance block from config' {
        $compliance = @{ framework='ISO 27001'
                         summary='Custom summary for ISO 27001 A.5.18.'
                         controls=@('A.5.18 Access rights') }
        $df = @{ reviewer='boss'; review_id='ab'; snapshot_sha256=('s'*64)
                 decided_at=Get-UtcNowIso
                 decisions=@(@{group='G';sam='a';decision='retain';justification=''}) }
        $att = New-Attestation -Decision $df -SnapshotSha256 ('s'*64) -Controls @($compliance['controls'])
        $att['controls'] | Should -Contain 'A.5.18 Access rights'
        $report = New-EvidenceReport -Campaign 'C' -SnapshotSha256 ('s'*64) `
            -Attestations @($att) -ExpectedReviewers @('boss') -Compliance $compliance
        $report | Should -Match 'ISO 27001 A.5.18'
    }
}

Describe 'Invoke-AdcertPreflight (config-only checks)' {
    It 'errors when the config has no groups' {
        $r = Invoke-AdcertPreflight -Config @{} -SkipAD
        @($r.Errors).Count | Should -BeGreaterThan 0
        ($r.Errors -join ' ') | Should -Match "no 'groups' list"
    }
    It 'warns about a group with no plain_language description' {
        $cfg = @{ groups = @(@{ name = 'G1' }) }
        $r = Invoke-AdcertPreflight -Config $cfg -SkipAD
        ($r.Warnings -join ' ') | Should -Match 'no plain_language'
    }
    It 'warns when a reviewer mapping targets an unlisted group' {
        $cfg = @{ groups = @(@{ name = 'G1'; plain_language = 'p' })
                  reviewers = @{ 'G-Nonexistent' = 'boss'; '_escalation' = 'boss' } }
        $r = Invoke-AdcertPreflight -Config $cfg -SkipAD
        ($r.Warnings -join ' ') | Should -Match 'G-Nonexistent'
    }
    It 'warns when privileged_groups names an unlisted group' {
        $cfg = @{ groups = @(@{ name = 'G1'; plain_language = 'p' })
                  privileged_groups = @('G-Missing'); reviewers = @{ '_escalation' = 'b' } }
        $r = Invoke-AdcertPreflight -Config $cfg -SkipAD
        ($r.Warnings -join ' ') | Should -Match 'G-Missing'
    }
    It 'warns when no _escalation reviewer is configured' {
        $cfg = @{ groups = @(@{ name = 'G1'; plain_language = 'p' }) }
        $r = Invoke-AdcertPreflight -Config $cfg -SkipAD
        ($r.Warnings -join ' ') | Should -Match '_escalation'
    }
    It 'is clean for a well-formed config' {
        $cfg = @{ groups = @(@{ name = 'G1'; plain_language = 'Members can do a thing.' })
                  reviewers = @{ '_escalation' = 'boss' }
                  privileged_groups = @('G1') }
        $r = Invoke-AdcertPreflight -Config $cfg -SkipAD
        @($r.Errors).Count | Should -Be 0
        @($r.Warnings).Count | Should -Be 0
    }
}

Describe 'New-RemediationReport' {
    It 'flags a revocation that did not take effect' {
        $results = @(
            [ordered]@{ sam='jsmith'; group='App-Admins'; reviewer='manager1'
                        justification='disabled at separation'; status='removed' },
            [ordered]@{ sam='cwlee'; group='VPN-Users'; reviewer='manager1'
                        justification='contract ended'; status='still_present' }
        )
        $html = New-RemediationReport -Campaign 'UAR-Demo' -Domain 'adcert.lab' -Results $results
        $html | Should -Match 'STILL PRESENT'
        $html | Should -Match 'Removed'
        $html | Should -Match 'jsmith'
        $html | Should -Not -Match '__[A-Z_]+__'
    }
    It 'handles a campaign with no revocations' {
        $html = New-RemediationReport -Campaign 'C' -Domain 'd' -Results @()
        $html | Should -Match 'No revocations were recorded'
    }
    It 'escapes hostile justification text' {
        $results = @([ordered]@{ sam='a'; group='G'; reviewer='r'
                                 justification='<script>alert(1)</script>'; status='removed' })
        $html = New-RemediationReport -Campaign 'C' -Domain 'd' -Results $results
        $html | Should -Not -Match '<script>alert'
    }
}

Describe 'Test-AdcertChain (integrity verification)' {
    BeforeAll {
        function New-TestCampaign {
            param([switch]$Tamper)
            $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("adcert_" + [guid]::NewGuid().ToString('N').Substring(0,8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null

            $snap = New-TestSnapshot
            ConvertTo-Json $snap -Depth 10 | Set-Content -Path (Join-Path $dir 'snapshot.json') -Encoding UTF8
            $hash = Get-Sha256OfFile (Join-Path $dir 'snapshot.json')

            $pkgs = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 $hash -Config @{}
            $reviewers = @()
            foreach ($p in $pkgs) {
                ConvertTo-Json $p -Depth 10 |
                    Set-Content -Path (Join-Path $dir ("review_{0}_{1}.json" -f $p['reviewer'], $p['review_id'])) -Encoding UTF8
                $reviewers += $p['reviewer']
            }
            ConvertTo-Json ([ordered]@{ campaign='UAR-TEST'; snapshot_sha256=$hash; reviewers=$reviewers }) -Depth 5 |
                Set-Content -Path (Join-Path $dir 'campaign_manifest.json') -Encoding UTF8

            # one decision file + compiled attestation
            $first = $pkgs[0]
            $decisions = @()
            foreach ($e in $first['entries']) {
                $decisions += @{ group=$e['group']; sam=$e['sam']; decision='retain'; justification='' }
            }
            $df = [ordered]@{ reviewer=$first['reviewer']; review_id=$first['review_id']
                              snapshot_sha256=$hash; decided_at=(Get-UtcNowIso); decisions=$decisions }
            ConvertTo-Json $df -Depth 10 |
                Set-Content -Path (Join-Path $dir ("decisions_{0}_{1}.json" -f $first['reviewer'], $first['review_id'])) -Encoding UTF8

            $ev = Join-Path $dir 'evidence'
            New-Item -ItemType Directory -Path $ev -Force | Out-Null
            $att = New-Attestation -Decision (ConvertTo-Hashtable ($df | ConvertTo-Json -Depth 10 | ConvertFrom-Json)) -SnapshotSha256 $hash
            if ($Tamper) { $att['decisions'][0]['decision'] = 'revoke' }
            ConvertTo-Json @($att) -Depth 10 | Set-Content -Path (Join-Path $ev 'attestations.json') -Encoding UTF8
            $dir
        }
    }

    It 'verifies an untampered campaign end to end' {
        $dir = New-TestCampaign
        try {
            $results = Test-AdcertChain -CampaignDir $dir
            @($results).Count | Should -BeGreaterThan 2
            @($results | Where-Object { -not $_.ok }).Count | Should -Be 0
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'detects an attestation edited after the fact' {
        $dir = New-TestCampaign -Tamper
        try {
            $results = Test-AdcertChain -CampaignDir $dir
            @($results | Where-Object { -not $_.ok }).Count | Should -BeGreaterThan 0
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'detects a modified snapshot' {
        $dir = New-TestCampaign
        try {
            Add-Content -Path (Join-Path $dir 'snapshot.json') -Value ' '
            $results = Test-AdcertChain -CampaignDir $dir
            $snapLink = @($results | Where-Object { $_.link -eq 'snapshot -> manifest' })[0]
            $snapLink.ok | Should -Be $false
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Get-AdcertRevocations' {
    It 'extracts only revoke decisions from attestations' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("att_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
        $atts = @([ordered]@{
            reviewer = 'manager1'; decided_at = (Get-UtcNowIso)
            decisions = @(
                @{ group='App-Admins'; sam='jsmith'; decision='revoke'; justification='disabled' },
                @{ group='VPN-Users'; sam='awong'; decision='retain'; justification='' },
                @{ group='VPN-Users'; sam='cwlee'; decision='revoke'; justification='contract ended' }
            )
        })
        ConvertTo-Json $atts -Depth 10 | Set-Content -Path $tmp -Encoding UTF8
        try {
            $revs = Get-AdcertRevocations -AttestationsPath $tmp
            @($revs).Count | Should -Be 2
            @($revs | ForEach-Object { $_['sam'] }) | Should -Contain 'jsmith'
            @($revs | ForEach-Object { $_['sam'] }) | Should -Not -Contain 'awong'
            @($revs)[0]['reviewer'] | Should -Be 'manager1'
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    It 'throws a helpful error when attestations are missing' {
        { Get-AdcertRevocations -AttestationsPath 'C:\nope\attestations.json' } |
            Should -Throw -ExpectedMessage "*compile*"
    }
}

Describe 'New-CampaignReadme' {
    It 'maps the folder and lists each reviewer with their entry count' {
        $snap = New-TestSnapshot
        $pkgs = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 ('a' * 64) -Config @{}
        $manifest = [ordered]@{ campaign = 'UAR-TEST'; snapshot_sha256 = ('a' * 64)
                                reviewers = @($pkgs | ForEach-Object { $_['reviewer'] }) }
        $txt = New-CampaignReadme -Manifest $manifest -Packages $pkgs
        $txt | Should -Match 'UAR-TEST'
        $txt | Should -Match 'IF YOU ARE A REVIEWER'
        $txt | Should -Match 'reviewers'
        foreach ($p in $pkgs) { $txt | Should -Match ([regex]::Escape($p['reviewer'])) }
    }
}

Describe 'Get-AdcertReviewerFolder' {
    It 'returns the per-reviewer subfolder when it exists' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("adc_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        $sub = Join-Path (Join-Path $dir 'reviewers') 'manager1'
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        try {
            (Get-AdcertReviewerFolder -CampaignDir $dir -Reviewer 'manager1') | Should -Be $sub
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'falls back to the campaign root for older flat campaigns' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("adc_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            (Get-AdcertReviewerFolder -CampaignDir $dir -Reviewer 'nobody') | Should -Be $dir
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Invoke-AdcertCollect' {
    BeforeAll {
        function New-CollectFixture {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ("adc_" + [guid]::NewGuid().ToString('N').Substring(0,8))
            $camp = Join-Path $root 'campaign'
            $drop = Join-Path $root 'downloads'
            New-Item -ItemType Directory -Path (Join-Path (Join-Path $camp 'reviewers') 'manager1') -Force | Out-Null
            New-Item -ItemType Directory -Path $drop -Force | Out-Null

            $snap = New-TestSnapshot
            ConvertTo-Json $snap -Depth 10 | Set-Content -Path (Join-Path $camp 'snapshot.json') -Encoding UTF8
            $hash = Get-Sha256OfFile (Join-Path $camp 'snapshot.json')
            ConvertTo-Json ([ordered]@{ campaign='UAR-TEST'; snapshot_sha256=$hash
                                        reviewers=@('manager1') }) -Depth 5 |
                Set-Content -Path (Join-Path $camp 'campaign_manifest.json') -Encoding UTF8

            # a good file, a wrong-campaign file, an unknown-reviewer file, and junk
            ConvertTo-Json ([ordered]@{ reviewer='manager1'; review_id='aa'; snapshot_sha256=$hash
                                        decided_at=(Get-UtcNowIso); decisions=@() }) -Depth 5 |
                Set-Content -Path (Join-Path $drop 'decisions_manager1_aa.json') -Encoding UTF8
            ConvertTo-Json ([ordered]@{ reviewer='manager1'; review_id='bb'; snapshot_sha256=('z'*64)
                                        decided_at=(Get-UtcNowIso); decisions=@() }) -Depth 5 |
                Set-Content -Path (Join-Path $drop 'decisions_manager1_bb.json') -Encoding UTF8
            ConvertTo-Json ([ordered]@{ reviewer='stranger'; review_id='cc'; snapshot_sha256=$hash
                                        decided_at=(Get-UtcNowIso); decisions=@() }) -Depth 5 |
                Set-Content -Path (Join-Path $drop 'decisions_stranger_cc.json') -Encoding UTF8
            Set-Content -Path (Join-Path $drop 'decisions_broken.json') -Value 'not json' -Encoding UTF8

            @{ Root = $root; Campaign = $camp; Drop = $drop }
        }
    }

    It 'files a matching decisions file into the reviewer subfolder' {
        $f = New-CollectFixture
        try {
            $r = Invoke-AdcertCollect -CampaignDir $f.Campaign -From $f.Drop
            $moved = @($r | Where-Object { $_.Action -eq 'moved' })
            $moved.Count | Should -Be 1
            $moved[0].Reviewer | Should -Be 'manager1'
            (Test-Path (Join-Path (Join-Path (Join-Path $f.Campaign 'reviewers') 'manager1') 'decisions_manager1_aa.json')) |
                Should -Be $true
        } finally { Remove-Item $f.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'refuses a file from a different campaign' {
        $f = New-CollectFixture
        try {
            $r = Invoke-AdcertCollect -CampaignDir $f.Campaign -From $f.Drop
            $bad = @($r | Where-Object { $_.File -like '*_bb.json' })
            $bad[0].Action | Should -Be 'skipped'
            $bad[0].Reason | Should -Match 'different campaign'
        } finally { Remove-Item $f.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'refuses a reviewer who is not part of the campaign' {
        $f = New-CollectFixture
        try {
            $r = Invoke-AdcertCollect -CampaignDir $f.Campaign -From $f.Drop
            $bad = @($r | Where-Object { $_.File -like '*stranger*' })
            $bad[0].Action | Should -Be 'skipped'
            $bad[0].Reason | Should -Match 'not part of this campaign'
        } finally { Remove-Item $f.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'survives an unreadable file' {
        $f = New-CollectFixture
        try {
            $r = Invoke-AdcertCollect -CampaignDir $f.Campaign -From $f.Drop
            $bad = @($r | Where-Object { $_.File -like '*broken*' })
            $bad[0].Reason | Should -Match 'not readable'
        } finally { Remove-Item $f.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'moves nothing in DryRun mode' {
        $f = New-CollectFixture
        try {
            $r = Invoke-AdcertCollect -CampaignDir $f.Campaign -From $f.Drop -DryRun
            @($r | Where-Object { $_.Action -eq 'would move' }).Count | Should -Be 1
            (Test-Path (Join-Path $f.Drop 'decisions_manager1_aa.json')) | Should -Be $true
        } finally { Remove-Item $f.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
