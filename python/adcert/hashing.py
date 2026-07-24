"""SHA-256 helpers used for the evidence integrity chain.

Chain: snapshot hash -> embedded in each review package -> echoed in each
decision file -> attestation record hashes over (snapshot hash + decisions).
Any post-hoc edit to any artifact breaks the chain.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_canonical_json(obj) -> str:
    """Hash a JSON-serializable object with canonical key ordering so the
    hash is stable regardless of dict insertion order."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
