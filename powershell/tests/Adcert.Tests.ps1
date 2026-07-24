# Adcert.Tests.ps1 - Pester 5 tests for the adcert PowerShell module.
# Run on the VM (or any Windows box):
#   Install-Module Pester -Force -SkipPublisherCheck   # once
#   Invoke-Pester .\powershell\tests\Adcert.Tests.ps1
# No AD required - everything here exercises pure functions.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\Adcert.psm1') -Force

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
