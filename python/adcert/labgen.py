"""Synthetic AD snapshot generator (demo-safe mode).

Fabricates a plausible generic company so the tool can be demoed and
tested without touching production AD. Plants deliberate findings:

  * at least one DISABLED account still holding group membership
  * at least one long-dormant (>180 day) account in a privileged group
  * at least one account that has NEVER logged on
  * one account expiring soon (contractor pattern)

Deterministic under a fixed --seed so tests and demos are reproducible.
"""
from __future__ import annotations

import random
from datetime import timedelta

from .models import Group, Member, Snapshot, now_utc, to_iso

FIRST = ["Avery", "Jordan", "Riley", "Morgan", "Casey", "Quinn", "Rowan",
         "Emerson", "Skyler", "Dakota", "Reese", "Finley", "Harper", "Sage",
         "Kendall", "Parker", "Elliot", "Marlow", "Tatum", "Blair"]
LAST = ["Lindqvist", "Okafor", "Ramire", "Chen", "Novak", "Bergström",
        "Iwu", "Kowalski", "Haddad", "Ostrom", "Vang", "Petrov", "Delaney",
        "Moreno", "Askari", "Byrne", "Sorensen", "Ito", "Klein", "Marsh"]
TITLES = ["Analyst", "Associate", "Coordinator", "Team Manager",
          "Systems Administrator", "Director", "Engineer", "Specialist"]
DEPTS = ["Finance", "Operations", "Sales", "Marketing", "IT", "HR"]

DEFAULT_GROUPS = [
    ("Finance-App", "Access to the finance application",
     "Members can sign in to the finance application and view or edit financial records."),
    ("HR-Records", "Access to the HR records system",
     "Members can read and update employee records in the HR system."),
    ("VPN-Users", "Remote VPN access",
     "Members can connect to the corporate network remotely over the VPN."),
    ("App-Admins", "Application administrator rights (privileged)",
     "Members hold administrator rights over the application. Privileged group."),
]


def generate_lab(seed: int = 842, users: int = 28) -> Snapshot:
    users = max(10, users)  # need headroom for the planted findings
    rng = random.Random(seed)
    ref = now_utc()

    # --- build a pool of people with managers -------------------------------
    names = rng.sample([(f, l) for f in FIRST for l in LAST], users)
    people: list[Member] = []
    for i, (f, l) in enumerate(names):
        sam = (f[0] + l).lower()[:12] + (str(i) if i % 7 == 0 else "")
        title = rng.choice(TITLES)
        m = Member(
            sam=sam,
            display_name=f"{f} {l}",
            title=title,
            department=rng.choice(DEPTS),
            enabled=True,
            when_created=to_iso(ref - timedelta(days=rng.randint(90, 2200))),
            pwd_last_set=to_iso(ref - timedelta(days=rng.randint(1, 170))),
            last_logon=to_iso(ref - timedelta(days=rng.randint(0, 45),
                                              hours=rng.randint(0, 23))),
        )
        people.append(m)

    # supervisors: first 4 people manage everyone else round-robin
    supervisors = people[:4]
    for i, p in enumerate(people[4:]):
        p.manager_sam = supervisors[i % 4].sam
    for s in supervisors:
        s.title = "PI"

    # --- planted findings ---------------------------------------------------
    dormant = people[5]
    dormant.last_logon = to_iso(ref - timedelta(days=rng.randint(190, 320)))

    disabled = people[6]
    disabled.enabled = False
    disabled.last_logon = to_iso(ref - timedelta(days=140))

    never = people[7]
    never.last_logon = None

    contractor = people[8]
    contractor.title = "Contractor"
    contractor.account_expires = to_iso(ref + timedelta(days=12))

    # --- assign memberships -------------------------------------------------
    groups: list[Group] = []
    for gi, (name, desc, plain) in enumerate(DEFAULT_GROUPS):
        g = Group(name=name, ad_description=desc, plain_language=plain)
        pool = people if gi < 3 else supervisors + [dormant, disabled]
        k = rng.randint(max(4, len(pool) // 3), max(5, int(len(pool) * 0.7)))
        g.members = sorted(rng.sample(pool, min(k, len(pool))),
                           key=lambda m: m.sam)
        groups.append(g)

    # guarantee the planted findings are visible in group 0 and the priv group
    for planted in (dormant, disabled, never, contractor):
        if planted not in groups[0].members:
            groups[0].members.append(planted)
    if dormant not in groups[3].members:
        groups[3].members.append(dormant)
    if disabled not in groups[3].members:
        groups[3].members.append(disabled)
    for g in groups:
        g.members.sort(key=lambda m: m.sam)

    return Snapshot(generated_at=to_iso(ref), source="labgen", groups=groups)
