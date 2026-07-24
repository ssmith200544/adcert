"""Review builder.

Turns an access snapshot into per-reviewer review packages:

  * enrichment  - human-readable context (days dormant, flags) per entry
  * risk sort   - riskiest entries float to the top of each package
  * diff        - entries new since the prior cycle's snapshot are marked
  * routing     - group -> reviewer from config, falling back to the AD
                  manager attribute of each member

The "humane" design goals: each reviewer sees only their own people, every
row carries the context needed to decide, and the risky rows lead.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from .models import Snapshot, Member, from_iso, now_utc, to_iso

DORMANT_DAYS = 90          # threshold for the dormancy flag
STALE_TOLERANCE_NOTE = ("lastLogonTimestamp replicates lazily and may be up to "
                        "14 days stale; treat dormancy as approximate.")


@dataclass
class ReviewEntry:
    group: str
    group_plain: str
    sam: str
    display_name: str
    title: str
    department: str
    enabled: bool
    last_logon: Optional[str]
    days_since_logon: Optional[int]
    account_expires: Optional[str]
    flags: list[str] = field(default_factory=list)
    risk: int = 0
    new_since_last_review: bool = False


@dataclass
class ReviewPackage:
    review_id: str
    reviewer: str
    campaign: str
    snapshot_sha256: str
    generated_at: str
    entries: list[ReviewEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ scoring

def score_entry(m: Member, group_name: str, privileged_groups: set[str],
                ref=None) -> tuple[int, list[str]]:
    """Return (risk score, human-readable flags) for one membership."""
    ref = ref or now_utc()
    risk, flags = 0, []
    days = m.days_since_logon(ref)

    if not m.enabled:
        risk += 50
        flags.append("Account is DISABLED but still holds this membership")
    if days is None:
        risk += 30
        flags.append("Account has never logged on")
    elif days >= DORMANT_DAYS:
        risk += 20 + min(30, days // 30)
        flags.append(f"Dormant: last logon {days} days ago")

    exp = from_iso(m.account_expires)
    if exp is not None:
        delta = (exp - ref).days
        if delta < 0:
            risk += 40
            flags.append("Account expiration date has passed")
        elif delta <= 30:
            risk += 10
            flags.append(f"Account expires in {delta} days")

    if group_name in privileged_groups:
        risk = int(risk * 1.5) + 5
        flags.append("Privileged group")

    return risk, flags


# ------------------------------------------------------------------- diffing

def membership_set(snap: Snapshot) -> set[tuple[str, str]]:
    return {(g.name, m.sam) for g in snap.groups for m in g.members}


# ------------------------------------------------------------------ building

def build_packages(snapshot: Snapshot,
                   snapshot_sha256: str,
                   reviewer_map: dict[str, str],
                   privileged_groups: set[str] | None = None,
                   prior_snapshot: Snapshot | None = None,
                   campaign: str = "") -> list[ReviewPackage]:
    """reviewer_map: group name -> reviewer sam. A member whose group has no
    mapped reviewer is routed to that member's own AD manager. Entries with
    no resolvable reviewer land in an '_unrouted' package so nothing is
    silently dropped."""
    privileged_groups = privileged_groups or set()
    prior = membership_set(prior_snapshot) if prior_snapshot else None
    ref = now_utc()
    campaign = campaign or f"UAR-{ref.strftime('%Y-%m')}"

    buckets: dict[str, list[ReviewEntry]] = {}
    for g in snapshot.groups:
        for m in g.members:
            reviewer = reviewer_map.get(g.name) or m.manager_sam or "_unrouted"
            # a reviewer never certifies their own access
            if reviewer == m.sam:
                reviewer = reviewer_map.get("_escalation", "_unrouted")
            risk, flags = score_entry(m, g.name, privileged_groups, ref)
            entry = ReviewEntry(
                group=g.name,
                group_plain=g.plain_language or g.ad_description,
                sam=m.sam,
                display_name=m.display_name,
                title=m.title,
                department=m.department,
                enabled=m.enabled,
                last_logon=m.last_logon,
                days_since_logon=m.days_since_logon(ref),
                account_expires=m.account_expires,
                flags=flags,
                risk=risk,
                new_since_last_review=(prior is not None
                                       and (g.name, m.sam) not in prior),
            )
            buckets.setdefault(reviewer, []).append(entry)

    packages = []
    for reviewer, entries in sorted(buckets.items()):
        entries.sort(key=lambda e: (-e.risk, e.group, e.sam))
        packages.append(ReviewPackage(
            review_id=str(uuid.uuid4())[:8],
            reviewer=reviewer,
            campaign=campaign,
            snapshot_sha256=snapshot_sha256,
            generated_at=to_iso(ref),
            entries=entries,
        ))
    return packages
