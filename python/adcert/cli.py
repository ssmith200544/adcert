"""adcert command line interface.

Subcommands:
  generate-lab     write a synthetic AD snapshot (demo-safe mode)
  build-reviews    snapshot + config -> per-reviewer packages (JSON + HTML)
  compile-evidence decision files -> attestations, report, revocation script
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import labgen
from .hashing import sha256_file
from .html_review import render_review_html
from .models import Snapshot
from .review import build_packages, STALE_TOLERANCE_NOTE
from .evidence import (build_attestation, build_report,
                       build_revocation_script, load_decision_file,
                       validate_decision_file)


def _load_snapshot(path: Path) -> tuple[Snapshot, str]:
    with open(path, encoding="utf-8") as f:
        snap = Snapshot.from_dict(json.load(f))
    return snap, sha256_file(path)


def cmd_generate_lab(args) -> int:
    snap = labgen.generate_lab(seed=args.seed, users=args.users)
    out = Path(args.out)
    out.write_text(json.dumps(snap.to_dict(), indent=2), encoding="utf-8")
    print(f"[+] Synthetic snapshot written: {out}")
    print(f"    groups={len(snap.groups)} "
          f"memberships={sum(len(g.members) for g in snap.groups)}")
    print(f"    sha256={sha256_file(out)}")
    return 0


def cmd_build_reviews(args) -> int:
    snap, snap_hash = _load_snapshot(Path(args.snapshot))
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    reviewer_map = cfg.get("reviewers", {})
    privileged = set(cfg.get("privileged_groups", []))
    prior = None
    if args.prior:
        prior, _ = _load_snapshot(Path(args.prior))

    packages = build_packages(snap, snap_hash, reviewer_map,
                              privileged_groups=privileged,
                              prior_snapshot=prior,
                              campaign=args.campaign)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = {"campaign": packages[0].campaign if packages else args.campaign,
                "snapshot_sha256": snap_hash,
                "reviewers": []}
    for pkg in packages:
        base = outdir / f"review_{pkg.reviewer}_{pkg.review_id}"
        base.with_suffix(".json").write_text(
            json.dumps(pkg.to_dict(), indent=2), encoding="utf-8")
        base.with_suffix(".html").write_text(
            render_review_html(pkg, STALE_TOLERANCE_NOTE), encoding="utf-8")
        manifest["reviewers"].append(pkg.reviewer)
        tag = " [UNROUTED — assign manually]" if pkg.reviewer == "_unrouted" else ""
        print(f"[+] {pkg.reviewer:<16} {len(pkg.entries):>3} entries -> "
              f"{base.name}.html{tag}")
    (outdir / "campaign_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[+] Manifest: {outdir/'campaign_manifest.json'}")
    return 0


def cmd_compile_evidence(args) -> int:
    snap, snap_hash = _load_snapshot(Path(args.snapshot))
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if manifest["snapshot_sha256"] != snap_hash:
        print("[!] Snapshot does not match the manifest hash — wrong file?",
              file=sys.stderr)
        return 2

    # expected (group, sam) pairs per reviewer come from the review packages
    pkg_dir = Path(args.manifest).parent
    expected: dict[str, set] = {}
    for pj in pkg_dir.glob("review_*.json"):
        pkg = json.loads(pj.read_text(encoding="utf-8"))
        expected[pkg["reviewer"]] = {(e["group"], e["sam"])
                                     for e in pkg["entries"]}

    attestations, strict_fail = [], False
    for dpath in sorted(Path(args.decisions).glob("decisions_*.json")):
        df = load_decision_file(dpath)
        problems = validate_decision_file(
            df, snap_hash, expected.get(df.reviewer, set()))
        if problems:
            print(f"[!] {dpath.name}:")
            for p in problems:
                print(f"      - {p}")
            if args.strict:
                strict_fail = True
                continue
        attestations.append(build_attestation(df, snap_hash))
        print(f"[+] Attested: {df.reviewer} "
              f"({len(df.decisions)} decisions)")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "attestations.json").write_text(
        json.dumps(attestations, indent=2), encoding="utf-8")
    (outdir / "revocation_worklist.ps1").write_text(
        build_revocation_script(attestations), encoding="utf-8")
    (outdir / "evidence_report.html").write_text(
        build_report(manifest["campaign"], snap_hash, attestations,
                     manifest["reviewers"]), encoding="utf-8")
    print(f"[+] Evidence written to {outdir}/")
    return 3 if strict_fail else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="adcert",
        description="Humane periodic access reviews for AD-backed CUI enclaves "
                    "(NIST SP 800-171 AC.L2-3.1.1 / 3.1.2).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate-lab", help="write a synthetic demo snapshot")
    g.add_argument("--out", default="snapshot_lab.json")
    g.add_argument("--seed", type=int, default=842)
    g.add_argument("--users", type=int, default=28)
    g.set_defaults(fn=cmd_generate_lab)

    b = sub.add_parser("build-reviews", help="build per-reviewer packages")
    b.add_argument("--snapshot", required=True)
    b.add_argument("--config", required=True)
    b.add_argument("--prior", help="prior cycle snapshot for diffing")
    b.add_argument("--campaign", default="")
    b.add_argument("--outdir", default="campaign")
    b.set_defaults(fn=cmd_build_reviews)

    c = sub.add_parser("compile-evidence", help="compile returned decisions")
    c.add_argument("--snapshot", required=True)
    c.add_argument("--manifest", required=True)
    c.add_argument("--decisions", required=True,
                   help="directory containing decisions_*.json files")
    c.add_argument("--outdir", default="evidence")
    c.add_argument("--strict", action="store_true",
                   help="exclude decision files with validation problems")
    c.set_defaults(fn=cmd_compile_evidence)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
