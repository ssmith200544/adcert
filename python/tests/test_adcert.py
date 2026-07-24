"""adcert test suite — pure-function coverage of scoring, routing, diffing,
decision validation, and the evidence integrity chain."""
import json
from datetime import timedelta

import pytest

from adcert import labgen
from adcert.hashing import sha256_canonical_json
from adcert.models import (Decision, DecisionFile, Member, Snapshot,
                           now_utc, to_iso)
from adcert.review import build_packages, membership_set, score_entry
from adcert.evidence import (build_attestation, build_report,
                             build_revocation_script, summarize,
                             validate_decision_file)


REF = now_utc()


def member(**kw):
    base = dict(sam="jdoe", display_name="J Doe", enabled=True,
                last_logon=to_iso(REF - timedelta(days=5)))
    base.update(kw)
    return Member(**base)


# ------------------------------------------------------------------ scoring

class TestScoring:
    def test_active_recent_user_low_risk(self):
        risk, flags = score_entry(member(), "G", set(), REF)
        assert risk == 0 and flags == []

    def test_disabled_account_flagged(self):
        risk, flags = score_entry(member(enabled=False), "G", set(), REF)
        assert risk >= 50
        assert any("DISABLED" in f for f in flags)

    def test_never_logged_on(self):
        risk, flags = score_entry(member(last_logon=None), "G", set(), REF)
        assert risk >= 30
        assert any("never logged on" in f.lower() for f in flags)

    def test_dormancy_scales_with_days(self):
        r90, _ = score_entry(member(last_logon=to_iso(REF - timedelta(days=95))),
                             "G", set(), REF)
        r300, _ = score_entry(member(last_logon=to_iso(REF - timedelta(days=300))),
                              "G", set(), REF)
        assert r300 > r90 > 0

    def test_under_threshold_not_dormant(self):
        _, flags = score_entry(member(last_logon=to_iso(REF - timedelta(days=89))),
                               "G", set(), REF)
        assert not any("Dormant" in f for f in flags)

    def test_privileged_group_multiplier(self):
        m = member(last_logon=to_iso(REF - timedelta(days=120)))
        plain, _ = score_entry(m, "G", set(), REF)
        priv, flags = score_entry(m, "G", {"G"}, REF)
        assert priv > plain
        assert any("Privileged" in f for f in flags)

    def test_expired_account(self):
        _, flags = score_entry(member(account_expires=to_iso(REF - timedelta(days=3))),
                               "G", set(), REF)
        assert any("passed" in f for f in flags)

    def test_expiring_soon(self):
        _, flags = score_entry(member(account_expires=to_iso(REF + timedelta(days=10))),
                               "G", set(), REF)
        assert any("expires in" in f for f in flags)


# ------------------------------------------------------------------ routing

def snap_with(reviewer_setup):
    lab = labgen.generate_lab(seed=1, users=12)
    return lab


class TestRouting:
    def test_group_mapping_wins_over_manager(self):
        snap = labgen.generate_lab(seed=1, users=12)
        gname = snap.groups[0].name
        pkgs = build_packages(snap, "h" * 64, {gname: "secadmin"})
        by_rev = {p.reviewer: p for p in pkgs}
        assert "secadmin" in by_rev
        assert all(e.group == gname for e in by_rev["secadmin"].entries)

    def test_manager_fallback(self):
        snap = labgen.generate_lab(seed=1, users=12)
        pkgs = build_packages(snap, "h" * 64, {})
        # supervisors have no manager themselves -> some routing to _unrouted
        reviewers = {p.reviewer for p in pkgs}
        managed = {m.manager_sam for g in snap.groups
                   for m in g.members if m.manager_sam}
        assert managed & reviewers

    def test_no_self_certification(self):
        snap = labgen.generate_lab(seed=1, users=12)
        pkgs = build_packages(snap, "h" * 64,
                              {g.name: "escrow" for g in snap.groups} |
                              {"_escalation": "secadmin"})
        for p in pkgs:
            for e in p.entries:
                assert e.sam != p.reviewer or p.reviewer == "_unrouted"

    def test_nothing_dropped(self):
        snap = labgen.generate_lab(seed=1, users=12)
        total = sum(len(g.members) for g in snap.groups)
        pkgs = build_packages(snap, "h" * 64, {})
        assert sum(len(p.entries) for p in pkgs) == total

    def test_risk_sorted_descending(self):
        snap = labgen.generate_lab(seed=842)
        for p in build_packages(snap, "h" * 64, {}):
            risks = [e.risk for e in p.entries]
            assert risks == sorted(risks, reverse=True)


# ------------------------------------------------------------------- diffing

class TestDiff:
    def test_new_membership_marked(self):
        prior = labgen.generate_lab(seed=842)
        current = labgen.generate_lab(seed=842)
        newbie = Member(sam="brandnew", display_name="Brand New",
                        last_logon=to_iso(REF))
        current.groups[0].members.append(newbie)
        pkgs = build_packages(current, "h" * 64, {}, prior_snapshot=prior)
        marked = [e for p in pkgs for e in p.entries if e.new_since_last_review]
        assert {e.sam for e in marked} == {"brandnew"}

    def test_no_prior_means_no_marks(self):
        snap = labgen.generate_lab(seed=842)
        pkgs = build_packages(snap, "h" * 64, {})
        assert not any(e.new_since_last_review
                       for p in pkgs for e in p.entries)

    def test_membership_set(self):
        snap = labgen.generate_lab(seed=842)
        pairs = membership_set(snap)
        assert len(pairs) == sum(len(g.members) for g in snap.groups)


# ------------------------------------------------------------------- labgen

class TestLabgen:
    def test_deterministic(self):
        a = labgen.generate_lab(seed=7).to_dict()
        b = labgen.generate_lab(seed=7).to_dict()
        a["generated_at"] = b["generated_at"] = "X"
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_planted_findings_present(self):
        snap = labgen.generate_lab(seed=842)
        members = [m for g in snap.groups for m in g.members]
        assert any(not m.enabled for m in members)
        assert any(m.last_logon is None for m in members)
        assert any((m.days_since_logon() or 0) > 180 for m in members)
        assert any(m.account_expires for m in members)

    def test_roundtrip_serialization(self):
        snap = labgen.generate_lab(seed=3)
        again = Snapshot.from_dict(json.loads(json.dumps(snap.to_dict())))
        assert membership_set(snap) == membership_set(again)


# ---------------------------------------------------------------- validation

def decision_file(pairs, snapshot_hash="s" * 64, reviewer="boss",
                  decision="retain", justification=""):
    return DecisionFile(
        reviewer=reviewer, review_id="abcd1234",
        snapshot_sha256=snapshot_hash, decided_at=to_iso(REF),
        decisions=[Decision(group=g, sam=s, decision=decision,
                            justification=justification) for g, s in pairs])


class TestValidation:
    EXPECTED = {("G1", "jdoe"), ("G1", "asmith")}

    def test_clean_file(self):
        df = decision_file(self.EXPECTED)
        assert validate_decision_file(df, "s" * 64, self.EXPECTED) == []

    def test_wrong_snapshot_hash_breaks_chain(self):
        df = decision_file(self.EXPECTED, snapshot_hash="x" * 64)
        problems = validate_decision_file(df, "s" * 64, self.EXPECTED)
        assert any("integrity chain" in p for p in problems)

    def test_revoke_requires_justification(self):
        df = decision_file(self.EXPECTED, decision="revoke")
        problems = validate_decision_file(df, "s" * 64, self.EXPECTED)
        assert any("without justification" in p for p in problems)

    def test_missing_decision_detected(self):
        df = decision_file({("G1", "jdoe")})
        problems = validate_decision_file(df, "s" * 64, self.EXPECTED)
        assert any("no decision recorded" in p for p in problems)

    def test_out_of_scope_decision_detected(self):
        df = decision_file(self.EXPECTED | {("G9", "intruder")})
        problems = validate_decision_file(df, "s" * 64, self.EXPECTED)
        assert any("not part of this reviewer's package" in p for p in problems)

    def test_invalid_decision_value(self):
        df = decision_file(self.EXPECTED, decision="approve")
        problems = validate_decision_file(df, "s" * 64, self.EXPECTED)
        assert any("invalid decision" in p for p in problems)


# ------------------------------------------------------------------ evidence

class TestEvidence:
    def test_attestation_hash_stable_and_tamper_evident(self):
        df = decision_file({("G1", "jdoe")})
        att = build_attestation(df, "s" * 64)
        recorded = att.pop("attestation_sha256")
        assert recorded == sha256_canonical_json(att)
        att["decisions"][0]["decision"] = "revoke"   # tamper
        assert recorded != sha256_canonical_json(att)

    def test_revocation_script_only_revokes(self):
        df = decision_file({("G1", "jdoe")}, decision="revoke",
                           justification="left the project")
        script = build_revocation_script([build_attestation(df, "s" * 64)])
        assert "Remove-ADGroupMember -Identity 'G1' -Members 'jdoe'" in script
        assert "$Commit = $false" in script
        retain = decision_file({("G1", "x")})
        script2 = build_revocation_script([build_attestation(retain, "s" * 64)])
        assert "No revocations" in script2

    def test_summary_counts(self):
        a = build_attestation(decision_file({("G", "a"), ("G", "b")}), "s" * 64)
        c = summarize([a])
        assert c["retain"] == 2 and c["revoke"] == 0

    def test_report_lists_outstanding_reviewers(self):
        df = decision_file({("G1", "jdoe")})
        report = build_report("UAR-TEST", "s" * 64,
                              [build_attestation(df, "s" * 64)],
                              expected_reviewers=["boss", "slacker"])
        assert "slacker" in report
        assert "AC.L2-3.1.1" in report

    def test_report_escapes_html(self):
        df = decision_file({("G1", "jdoe")}, decision="revoke",
                           justification="<script>alert(1)</script>")
        report = build_report("UAR-TEST", "s" * 64,
                              [build_attestation(df, "s" * 64)], ["boss"])
        assert "<script>alert(1)</script>" not in report
