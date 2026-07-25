# adcert — Periodic Access Review, Made Humane

**CSC-842 Security Tool Development — Human, Privacy, & Trust-Centered Security**

adcert turns the quarterly access-review ritual — a spreadsheet emailed to
supervisors who rubber-stamp it — into a small, focused, evidence-producing
workflow for any organization that runs Active Directory. It helps satisfy the
periodic user-access-review (access recertification) control common to SOC 2,
ISO 27001, HIPAA, PCI DSS, NIST 800-53/800-171, and general IT audit.

The design thesis: **reviewers rubber-stamp because they lack context, not
because they don't care.** Give a supervisor only *their* people, lead with
the risky rows, translate group names into plain language, show last-logon
context at the moment of decision — and the review becomes real.

**PowerShell-native.** The entire workflow runs on any domain-joined Windows
box with RSAT — no Python, no server, no file transfers between machines.
One command produces the reviewer HTML pages directly from AD.

## Workflow

```
1. New-AdcertCampaign.ps1      AD -> a campaign folder containing scored,
                               routed, self-contained HTML review pages
2. (reviewers)                 open their HTML page, decide every row, click
                               Export - saved straight back into the campaign
                               folder (Save As dialog on Edge/Chrome)
3. Compile-AdcertEvidence.ps1 <campaign folder>
                               that's the whole command - finds the decision
                               files itself, writes evidence\ inside the
                               campaign folder, reports who's outstanding
```

The campaign folder is the only location in the workflow: pages come out of
it, decisions go back into it, evidence appears inside it. Each stage prints
the exact next command with your paths filled in.

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
- Run `Seed-DemoLab.ps1` to create the fictional company, then the two
  campaign commands below.

The Pester test suite (`powershell/tests/Adcert.Tests.ps1`) exercises the
scoring, routing, and evidence logic **without** Active Directory, so it can
be run on any Windows machine to verify the engine.

## Quick start

```powershell
cd powershell

# create a campaign (collects live from AD)
.\New-AdcertCampaign.ps1 -Config ..\config\groups.json -OutDir C:\adcert\UAR-2026-Q3

# ... reviewers open review_*.html from that folder, decide, Export ...

.\Compile-AdcertEvidence.ps1 C:\adcert\UAR-2026-Q3
```

Next cycle, pass `-PriorSnapshot <last campaign>\snapshot.json` and reviewers
see what changed since the last review instead of re-reading the same rows.

For a demo lab: promote a throwaway DC as `adcert.lab`, then

```powershell
.\Seed-DemoLab.ps1     # 9 users, 11 access grants, sized for a video demo
.\New-AdcertCampaign.ps1 -Config ..\config\groups-demo.json -OutDir C:\adcert\UAR-Demo
```

`Seed-DemoLab.ps1` produces three small review packages (6 / 3 / 2 entries)
carrying every planted finding: a disabled account still in the privileged
group, an expiring contractor, never-logged-on accounts, and a nested group
proving recursive resolution. `Remove-LabAD.ps1` tears it down again; the
seeder and the teardown both refuse to run against any domain but `adcert.lab`.

## What it produces

| Artifact | Purpose |
|---|---|
| Per-reviewer HTML review page | Self-contained, no server, works air-gapped. Retain / Revoke / Modify with required justifications. |
| Attestation records (JSON) | Hash-chained to the snapshot; tamper-evident. |
| Evidence report (HTML) | Auditor-facing summary mapped to the access-review / least-privilege controls of whichever framework you configure (SOC 2, ISO 27001, HIPAA, PCI DSS, NIST). |
| Revocation worklist (.ps1) | Generated `Remove-ADGroupMember` commands, `-WhatIf` by default — decisions actually get executed. |
| Outstanding tracker | Reviewers who haven't returned decisions (in the report). |

## Design decisions

* **One runtime, one machine** — Windows PowerShell 5.1 (stock on Server
  2016+). Collection, scoring, HTML generation, and evidence compilation all
  run where the data lives. Nothing to install on a server, nothing to
  accredit.
* **Static HTML instead of a web app** — the reviewer interface is a file,
  not a service: no server to stand up, delivery over email or file share,
  works air-gapped.
* **Last-logon honesty** — the collector takes the most recent of
  `lastLogonTimestamp` (replicated, up to 14 days stale) and `lastLogon`
  (per-DC, immediate), and the review page carries the staleness caveat
  rather than presenting false precision.
* **Integrity chain** — snapshot SHA-256 → embedded in every review package →
  echoed in every decision file → hashed into every attestation
  (canonical-JSON SHA-256). Any post-hoc edit breaks the chain; `-Strict`
  mode refuses broken files.
* **Revocations ship commented-safe** — `-WhatIf` until an operator sets
  `$Commit = $true`.
* **Nothing silently dropped** — grants with no resolvable reviewer land in
  an explicit `_unrouted` package; a reviewer never certifies their own
  access (rerouted via the `_escalation` mapping).

## Configuration (`config/groups.json`)

* `groups[].plain_language` — the sentence a supervisor actually reads
  ("Members can sign in to the finance application"). Write it for the reviewer,
  not the sysadmin.
* `reviewers` — group → reviewer routing; unmapped members route to their
  own AD `manager` attribute; `_escalation` catches would-be
  self-certifications.
* `privileged_groups` — risk multiplier + flag.

## Tests

PowerShell (Pester 5, no AD required):

```powershell
Install-Module Pester -Force -SkipPublisherCheck   # once
Invoke-Pester .\powershell\tests\Adcert.Tests.ps1
```

`python/` contains the original reference implementation of the same scoring,
routing, and evidence logic with a 30-case pytest suite
(`python -m pytest python/tests -q`), kept for cross-validation.

## Related work

Access certification is a mature commercial category (SailPoint, Saviynt,
Okta Identity Governance; several vendors market compliance evidence reports) and
open-source IAM suites (midPoint, OpenIAM) include certification campaigns.
All of these assume you deploy an identity-governance *platform*. adcert
targets the gap below them: a small or mid-size organization (dozens to a few
hundred users, one admin) where the realistic alternative isn't SailPoint — it's
a spreadsheet. adcert reads the AD you already have, requires no server, and
shapes its output around what an auditor asks for.

## Future work

Email delivery of review packages; Entra ID collector via Microsoft Graph;
scheduled campaign mode; optional SIEM ingestion of attestation records.

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
