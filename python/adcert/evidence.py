"""Evidence engine.

Consumes returned decision files and produces the four campaign outputs:

  1. attestation record (JSON)  - per reviewer, hash-chained to the snapshot
  2. evidence report (HTML)     - assessor-facing campaign summary mapped to
                                  periodic access review and least-privilege
                                  controls common to SOC 2, ISO 27001, HIPAA,
                                  PCI DSS, and NIST
  3. revocation worklist (.ps1) - generated Remove-ADGroupMember commands,
                                  -WhatIf by default so nothing fires blind
  4. outstanding tracker         - reviewers who have not returned decisions
"""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .hashing import sha256_canonical_json
from .models import DecisionFile, VALID_DECISIONS, now_utc, to_iso

CONTROLS = ["Periodic access review", "Least-privilege enforcement", "Timely access revocation"]


class EvidenceError(ValueError):
    pass


def validate_decision_file(df: DecisionFile, snapshot_sha256: str,
                           expected_pairs: set[tuple[str, str]]) -> list[str]:
    """Returns a list of problems (empty list = clean)."""
    problems = []
    if df.snapshot_sha256 != snapshot_sha256:
        problems.append("decision file references a different snapshot hash "
                        "(integrity chain broken)")
    seen = set()
    for d in df.decisions:
        pair = (d.group, d.sam)
        if d.decision not in VALID_DECISIONS:
            problems.append(f"{pair}: invalid decision '{d.decision}'")
        if d.decision in ("revoke", "modify") and not d.justification.strip():
            problems.append(f"{pair}: '{d.decision}' without justification")
        if pair in seen:
            problems.append(f"{pair}: duplicate decision")
        if pair not in expected_pairs:
            problems.append(f"{pair}: not part of this reviewer's package")
        seen.add(pair)
    missing = expected_pairs - seen
    for pair in sorted(missing):
        problems.append(f"{pair}: no decision recorded")
    return problems


def build_attestation(df: DecisionFile, snapshot_sha256: str) -> dict:
    body = {
        "type": "adcert.attestation",
        "version": 1,
        "campaign_review_id": df.review_id,
        "reviewer": df.reviewer,
        "decided_at": df.decided_at,
        "compiled_at": to_iso(now_utc()),
        "snapshot_sha256": snapshot_sha256,
        "controls": CONTROLS[:2],
        "decisions": [vars(d) for d in df.decisions],
    }
    body["attestation_sha256"] = sha256_canonical_json(body)
    return body


def build_revocation_script(attestations: list[dict]) -> str:
    lines = [
        "# adcert revocation worklist — generated " + to_iso(now_utc()),
        "# Review before executing. Commands run with -WhatIf by default;",
        "# set $Commit = $true only after verifying the worklist.",
        "$Commit = $false",
        "$Flag = if ($Commit) { @{} } else { @{ WhatIf = $true } }",
        "Import-Module ActiveDirectory",
        "",
    ]
    n = 0
    for att in attestations:
        for d in att["decisions"]:
            if d["decision"] != "revoke":
                continue
            n += 1
            just = d["justification"].replace("`", "'").replace("\n", " ")
            lines.append(f"# {d['sam']} <- {d['group']}  "
                         f"(reviewer: {att['reviewer']}) — {just}")
            lines.append(f"Remove-ADGroupMember -Identity '{d['group']}' "
                         f"-Members '{d['sam']}' -Confirm:$false @Flag")
            lines.append("")
    if n == 0:
        lines.append("# No revocations were recorded in this campaign.")
    return "\n".join(lines) + "\n"


def summarize(attestations: list[dict]) -> Counter:
    c: Counter = Counter()
    for att in attestations:
        for d in att["decisions"]:
            c[d["decision"]] += 1
    return c


_REPORT = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Access Review Evidence — {campaign}</title>
<style>
 body{{font:15px/1.55 Georgia,serif;color:#1b2733;max-width:860px;margin:36px auto;padding:0 20px}}
 h1{{font-size:23px;border-bottom:3px solid #7a0019;padding-bottom:8px}}
 h2{{font-size:17px;margin-top:30px}}
 table{{border-collapse:collapse;width:100%;font-size:14px;font-family:"Segoe UI",sans-serif}}
 th,td{{border:1px solid #d7dde3;padding:6px 10px;text-align:left;vertical-align:top}}
 th{{background:#f0f2f4}}
 .kv{{font-family:"Segoe UI",sans-serif;font-size:14px}}
 .kv b{{display:inline-block;min-width:220px}}
 code{{font-size:12px;background:#f0f2f4;padding:1px 5px;border-radius:3px;word-break:break-all}}
 .controls{{background:#f6f7f8;border-left:4px solid #7a0019;padding:10px 16px;
            font-family:"Segoe UI",sans-serif;font-size:14px}}
</style></head><body>
<h1>Periodic Access Review — Evidence Report</h1>
<p class="kv">
 <b>Campaign:</b> {campaign}<br>
 <b>Compiled:</b> {compiled}<br>
 <b>Snapshot (SHA-256):</b> <code>{snap}</code><br>
 <b>Reviewers completed:</b> {done} of {total}<br>
 <b>Access grants reviewed:</b> {reviewed}
</p>
<div class="controls"><b>Control mapping:</b> This artifact evidences periodic
review of user access rights and enforcement of least privilege, supporting
access-recertification controls found in SOC 2 (CC6.1-CC6.3), ISO 27001
(A.5.18), HIPAA Security Rule (164.308(a)(4)), PCI DSS (Req. 7), and
NIST 800-53 (AC-2).</div>

<h2>Decision summary</h2>
<table><tr><th>Decision</th><th>Count</th></tr>{summary_rows}</table>

<h2>Reviewer attestations</h2>
<table><tr><th>Reviewer</th><th>Decided</th><th>Entries</th>
<th>Revoke</th><th>Attestation hash</th></tr>{att_rows}</table>

<h2>Revocations and modifications</h2>
{rev_section}

<h2>Outstanding reviewers</h2>
{outstanding}
<p style="color:#5b6b7a;font-family:'Segoe UI',sans-serif;font-size:12px">
Generated by adcert. Integrity chain: snapshot hash → reviewer decision files →
attestation hashes above. Recompute any attestation hash from its JSON record
to verify no post-review modification.</p>
</body></html>
"""


def build_report(campaign: str, snapshot_sha256: str,
                 attestations: list[dict], expected_reviewers: list[str]) -> str:
    counts = summarize(attestations)
    done_reviewers = {a["reviewer"] for a in attestations}
    outstanding = [r for r in expected_reviewers if r not in done_reviewers]

    summary_rows = "".join(
        f"<tr><td>{d.title()}</td><td>{counts.get(d, 0)}</td></tr>"
        for d in VALID_DECISIONS)

    att_rows = ""
    for a in attestations:
        rev = sum(1 for d in a["decisions"] if d["decision"] == "revoke")
        att_rows += (f"<tr><td>{html.escape(a['reviewer'])}</td>"
                     f"<td>{html.escape(a['decided_at'])}</td>"
                     f"<td>{len(a['decisions'])}</td><td>{rev}</td>"
                     f"<td><code>{a['attestation_sha256'][:16]}…</code></td></tr>")

    rev_rows = ""
    for a in attestations:
        for d in a["decisions"]:
            if d["decision"] in ("revoke", "modify"):
                rev_rows += (f"<tr><td>{html.escape(d['sam'])}</td>"
                             f"<td><code>{html.escape(d['group'])}</code></td>"
                             f"<td>{d['decision'].title()}</td>"
                             f"<td>{html.escape(a['reviewer'])}</td>"
                             f"<td>{html.escape(d['justification'])}</td></tr>")
    rev_section = ("<table><tr><th>Account</th><th>Group</th><th>Decision</th>"
                   "<th>Reviewer</th><th>Justification</th></tr>"
                   + rev_rows + "</table>") if rev_rows else \
                  "<p>No revocations or modifications this cycle.</p>"

    out_html = ("<p>All assigned reviewers have completed their review.</p>"
                if not outstanding else
                "<ul>" + "".join(f"<li>{html.escape(r)}</li>"
                                 for r in outstanding) + "</ul>")

    return _REPORT.format(
        campaign=html.escape(campaign),
        compiled=to_iso(now_utc()),
        snap=snapshot_sha256,
        done=len(done_reviewers),
        total=len(expected_reviewers),
        reviewed=sum(counts.values()),
        summary_rows=summary_rows,
        att_rows=att_rows or "<tr><td colspan=5>None returned yet.</td></tr>",
        rev_section=rev_section,
        outstanding=out_html,
    )


def load_decision_file(path: Path | str) -> DecisionFile:
    with open(path, encoding="utf-8") as f:
        return DecisionFile.from_dict(json.load(f))
