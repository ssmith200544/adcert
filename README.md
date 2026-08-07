# adcert — Periodic Access Review

adcert turns the quarterly access-review ritual — a spreadsheet emailed to
supervisors who rubber-stamp it — into a small, focused, evidence-producing
workflow for any organization that runs Active Directory. It helps satisfy the
periodic user-access-review (access recertification) control common to SOC 2,
ISO 27001, HIPAA, PCI DSS, NIST 800-53/800-171, and general IT audit.

The design thesis: **reviewers rubber-stamp because they lack context, not
because they don't care.** Give a supervisor only _their_ people, lead with
the risky rows, translate group names into plain language, show last-logon
context at the moment of decision — and the review becomes real.

**PowerShell-native.** The entire workflow runs on any domain-joined Windows
box with RSAT — no Python, no server, no file transfers between machines.
One command produces the reviewer HTML pages directly from AD.

## Workflow

There is one script, `adcert.ps1`, and it takes a verb:

```
adcert.ps1 preflight <config>     check config + directory data quality first
adcert.ps1 new       <config>     AD -> a campaign folder of scored, routed,
                                  self-contained HTML review pages, one
                                  subfolder per reviewer
adcert.ps1 send      <campaign>   email each reviewer their own page (-DryRun
                                  first; addresses come from AD)
   (reviewers)                    open their page, decide every row, click
                                  Export - saved back into their own subfolder
adcert.ps1 collect   <campaign>   rescue exported files that landed in
                                  Downloads and file them under the right
                                  reviewer
adcert.ps1 compile   <campaign>   decision files -> attestations, evidence
                                  report, and a revocation worklist
   (operator)                     run the generated revocation worklist
adcert.ps1 confirm   <campaign>   re-query AD: did the revocations actually
                                  take effect?
adcert.ps1 verify    <campaign>   independently re-check the integrity chain
```

The campaign folder is the only location in the workflow: pages come out of
it, decisions go back into it, evidence appears inside it. Each stage prints
the exact next command with your paths filled in. Run `.\adcert.ps1` with no
arguments for the verb list.

The folder stays readable no matter how many reviewers there are, because each
one gets a subfolder:

```
UAR-2026-Q3\
  README.txt                     plain-language map of this folder
  snapshot.json                  what the directory looked like at collection
  campaign_manifest.json         campaign metadata
  reviewers\
    manager1\
      review_manager1.html       the page this reviewer opens
      review_manager1.json       machine-readable copy
      decisions_manager1_*.json  saved back here when they finish
    _unrouted\
      ...
  evidence\                      created by 'compile' and 'confirm'
```

A reviewer can be handed just their own subfolder. The review page shows the
literal path it was opened from, so the reviewer is told exactly where to save
their decisions file rather than guessing.

## Requirements

adcert runs entirely in Windows PowerShell 5.1 (stock on Windows Server
2016 and later) and needs no other runtime — there is no Python, Node, or
package install involved in the tool itself.

To run against a live directory you need:

- A **Windows Server** host acting as, or joined to, an **Active Directory
  domain**, with the **RSAT ActiveDirectory PowerShell module** available
  (installed automatically with the AD DS role; otherwise add it with
  `Add-WindowsFeature RSAT-AD-PowerShell`).
- An account with **read access** to the groups being reviewed. Executing
  the generated revocation script additionally requires rights to modify
  those groups.
- A **web browser** (Edge or Chrome) for reviewers to open the HTML pages.

To reproduce the demo lab from scratch:

- A throwaway **Windows Server VM** (the free 180-day evaluation ISO is
  fine; 2 vCPU / 4 GB RAM is plenty).
- Promote it to a **domain controller** for a new forest named
  **`adcert.lab`** (the seeder and teardown scripts refuse to run against
  any other domain name, so they cannot touch a production directory).
- Run `.\adcert.ps1 lab seed` to create the fictional company, then the
  campaign verbs below.

The Pester test suite (`tests/Adcert.Tests.ps1`) exercises the
scoring, routing, and evidence logic **without** Active Directory, so it can
be run on any Windows machine to verify the engine.

## Quick start

Run everything from the repository root.

```powershell
# 1. sanity-check the config and directory before collecting anything
.\adcert.ps1 preflight -Config config\groups.json

# 2. build the campaign (collects live from AD)
.\adcert.ps1 new -Config config\groups.json -OutDir C:\adcert\UAR-2026-Q3

# 3. optional: email each reviewer their page (always dry-run first)
.\adcert.ps1 send C:\adcert\UAR-2026-Q3 -DryRun
.\adcert.ps1 send C:\adcert\UAR-2026-Q3

# ... reviewers open their page, decide, Export ...

# 4. optional: rescue any files that landed in Downloads
.\adcert.ps1 collect C:\adcert\UAR-2026-Q3

# 5. compile the evidence
.\adcert.ps1 compile C:\adcert\UAR-2026-Q3

# 6. after running evidence\revocation_worklist.ps1, prove it took effect
.\adcert.ps1 confirm C:\adcert\UAR-2026-Q3
```

Next cycle, pass `-PriorSnapshot <last campaign>\snapshot.json` to `new` and
reviewers see what changed since the last review instead of re-reading the
same rows.

For a demo lab: promote a throwaway DC as `adcert.lab`, then

```powershell
.\adcert.ps1 lab seed        # 6 users, 6 access grants, sized for a short demo
.\adcert.ps1 new -Config config\groups-demo.json -OutDir C:\adcert\UAR-Demo
```

The demo lab produces two small review packages (5 entries and 1 unrouted)
carrying every planted finding: a disabled account still in the privileged
group, an expiring contractor, never-logged-on accounts, and a nested group
proving recursive resolution. `.\adcert.ps1 lab remove` tears it down again;
the seeder and the teardown both refuse to run against any domain but
`adcert.lab`.

## What it produces

| Artifact                      | Purpose                                                                                                                                                      |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Per-reviewer HTML review page | Self-contained, no server, works air-gapped. Retain / Revoke / Modify with required justifications.                                                          |
| Attestation records (JSON)    | Hash-chained to the snapshot; tamper-evident.                                                                                                                |
| Evidence report (HTML)        | Auditor-facing summary mapped to the access-review / least-privilege controls of whichever framework you configure (SOC 2, ISO 27001, HIPAA, PCI DSS, NIST). |
| Revocation worklist (.ps1)    | Generated `Remove-ADGroupMember` commands, `-WhatIf` by default — decisions actually get executed.                                                           |
| Outstanding tracker           | Reviewers who haven't returned decisions (in the report).                                                                                                    |
| Remediation report (HTML)     | Written by `confirm`: per revoked grant, whether the access was actually removed from the directory. Closes the loop between the decision and the system.    |
| Preflight findings            | Written by `preflight` to the console: groups that don't exist, missing descriptions, grants with no reviewer, self-certification cases.                     |

## Closing the loop

Most access-review processes stop at approval, which is exactly the failure
this tool exists to fix. Two verbs push past it:

**`preflight`** runs before a campaign and reports the data-quality problems
that quietly degrade a review: groups in the config that don't exist in the
directory, groups with no plain-language description, reviewer mappings
pointing at accounts that aren't there, self-certification cases, and - the
big one - grants whose owner can't be resolved because the AD `manager`
attribute is blank. Those grants still get reviewed (they land in the
`_unrouted` package rather than disappearing), but preflight tells you how
many there are _before_ you send the campaign out, so you can fix the
directory or add an explicit mapping first.

**`confirm`** runs after the revocation worklist has been executed. It
re-queries Active Directory for every grant a reviewer revoked and records
whether the membership is actually gone, writing both a JSON status file and
an auditor-facing HTML report. This answers the question an auditor really
asks - not "did someone approve this?" but "did the decision take effect?" -
and it is the difference between a review that documents the process and one
that changes the system.

**`send`** emails each reviewer their own review page as an attachment, using
the `mail` attribute from their AD account and an `smtp` block in the config.
`-DryRun` shows exactly who would receive what, without contacting the mail
server. The `_unrouted` package is deliberately never emailed - it has no
owner by definition, so it is reported as skipped for manual assignment.

**`collect`** solves the mismatch between where a browser saves a file and
where the tool expects it. It scans Downloads, Desktop, and Documents (or a
folder you name with `-From`), and for each `decisions_*.json` it checks that
the file's snapshot hash matches this campaign and that the reviewer is one of
this campaign's reviewers before filing it into that reviewer's subfolder.
Files from another campaign, from an unknown reviewer, or that aren't readable
are reported and left alone.

**`verify`** independently recomputes the whole integrity chain (snapshot
hash, the hash embedded in each review package, the hash echoed by each
decision file, and each attestation's own hash over its contents) and prints
a pass/fail per link. It exists so a third party can validate the evidence
without having to trust the tool that produced it.

## Design decisions

- **One runtime, one entry point** — Windows PowerShell 5.1 (stock on Server
  2016+), and a single `adcert.ps1` that takes a verb. Collection, scoring,
  HTML generation, and evidence compilation all run where the data lives.
  Nothing to install on a server, nothing to accredit, and new capability
  arrives as a new verb rather than another script to remember.
- **Static HTML instead of a web app** — the reviewer interface is a file,
  not a service: no server to stand up, delivery over email or file share,
  works air-gapped.
- **Last-logon honesty** — the collector takes the most recent of
  `lastLogonTimestamp` (replicated, up to 14 days stale) and `lastLogon`
  (per-DC, immediate), and the review page carries the staleness caveat
  rather than presenting false precision.
- **Integrity chain** — snapshot SHA-256 → embedded in every review package →
  echoed in every decision file → hashed into every attestation
  (canonical-JSON SHA-256). Any post-hoc edit breaks the chain; `-Strict`
  mode refuses broken files.
- **Revocations ship commented-safe** — `-WhatIf` until an operator sets
  `$Commit = $true`.
- **Nothing silently dropped** — grants with no resolvable reviewer land in
  an explicit `_unrouted` package; a reviewer never certifies their own
  access (rerouted via the `_escalation` mapping).

## Configuration (`config/groups.json`)

- `groups[].plain_language` — the sentence a supervisor actually reads
  ("Members can sign in to the finance application"). Write it for the reviewer,
  not the sysadmin.
- `reviewers` — group → reviewer routing; unmapped members route to their
  own AD `manager` attribute; `_escalation` catches would-be
  self-certifications.
- `privileged_groups` — risk multiplier + flag.

## Tests

PowerShell (Pester 5, no AD required):

```powershell
Install-Module Pester -Force -SkipPublisherCheck   # once
Invoke-Pester .\tests\Adcert.Tests.ps1
```

`python/` contains the original reference implementation of the same scoring,
routing, and evidence logic with a 30-case pytest suite
(`python -m pytest python/tests -q`), kept for cross-validation.

## Related work

Access certification is a mature commercial category (SailPoint, Saviynt,
Okta Identity Governance; several vendors market compliance evidence reports) and
open-source IAM suites (midPoint, OpenIAM) include certification campaigns.
All of these assume you deploy an identity-governance _platform_. adcert
targets the gap below them: a small or mid-size organization (dozens to a few
hundred users, one admin) where the realistic alternative isn't SailPoint — it's
a spreadsheet. adcert reads the AD you already have, requires no server, and
shapes its output around what an auditor asks for.

## Future work

Entra ID collector via Microsoft Graph, for organizations moving identity to
the cloud; scheduled campaign mode so cycles run themselves; automatic intake
of decision files from a mailbox to complete the delivery loop; flagging
accounts retained while dormant across consecutive cycles; segregation-of-duties
conflict detection; optional SIEM ingestion of attestation and remediation
records.

## License

MIT

## AI usage

This project was developed with the assistance of an AI coding assistant
(Anthropic's Claude). AI was used to help design the tool's architecture,
draft and refactor the PowerShell module and scripts, generate the HTML
review interface and evidence report, write the test suites, and produce
documentation. All AI-generated code and content was reviewed, tested, and
validated by the author in a Windows Server / Active Directory lab before
inclusion. Design decisions, the choice of problem, the compliance framing,
and final verification of behavior are the author's own. AI was not used to
generate any real organizational data; all users, groups, and findings in
the demo lab are fictional.
