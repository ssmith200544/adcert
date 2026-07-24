"""Data models for adcert.

Everything is plain dataclasses serialized to/from JSON so the tool has
zero third-party dependencies (matches the stdlib-only philosophy of the
CSC-842 tool series).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


ISO = "%Y-%m-%dT%H:%M:%S%z"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime(ISO) if dt else None


def from_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # tolerate 'Z' suffix and missing colon in offset
    s = s.replace("Z", "+0000").replace("+00:00", "+0000")
    return datetime.strptime(s, ISO)


@dataclass
class Member:
    sam: str
    display_name: str
    title: str = ""
    department: str = ""
    manager_sam: str = ""
    enabled: bool = True
    last_logon: Optional[str] = None       # ISO 8601 or None (never logged on)
    pwd_last_set: Optional[str] = None
    when_created: Optional[str] = None
    account_expires: Optional[str] = None  # None = never

    def days_since_logon(self, ref: Optional[datetime] = None) -> Optional[int]:
        dt = from_iso(self.last_logon)
        if dt is None:
            return None
        ref = ref or now_utc()
        return max(0, (ref - dt).days)


@dataclass
class Group:
    name: str
    ad_description: str = ""
    plain_language: str = ""               # "Members can SSH to enclave HPC nodes"
    members: list[Member] = field(default_factory=list)


@dataclass
class Snapshot:
    generated_at: str
    source: str                            # e.g. "AD:umn.example" or "labgen"
    groups: list[Group] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Snapshot":
        groups = []
        for g in d.get("groups", []):
            members = [Member(**m) for m in g.get("members", [])]
            groups.append(Group(name=g["name"],
                                ad_description=g.get("ad_description", ""),
                                plain_language=g.get("plain_language", ""),
                                members=members))
        return Snapshot(generated_at=d["generated_at"],
                        source=d.get("source", "unknown"),
                        groups=groups)


# ---------------------------------------------------------------- decisions

VALID_DECISIONS = ("retain", "revoke", "modify")


@dataclass
class Decision:
    group: str
    sam: str
    decision: str                          # retain | revoke | modify
    justification: str = ""


@dataclass
class DecisionFile:
    reviewer: str
    review_id: str
    snapshot_sha256: str
    decided_at: str
    decisions: list[Decision] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict) -> "DecisionFile":
        return DecisionFile(
            reviewer=d["reviewer"],
            review_id=d["review_id"],
            snapshot_sha256=d["snapshot_sha256"],
            decided_at=d["decided_at"],
            decisions=[Decision(**x) for x in d.get("decisions", [])],
        )
