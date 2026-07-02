"""
crossestate/entropy.py
----------------------
Entropy / DGA scoring for discovery — the signal that separates the OWNED lane
(a legitimate brand extension you registered) from the HOSTILE lane (an
algorithmically-generated or typosquat lookalike an attacker registered).

Pure string functions (no corpus/model dependency): Shannon entropy over the
label, a DGA heuristic (entropy + digit ratio + long consonant runs), and a
cheap lookalike distance to a brand stem. The corpus-side `dga_risk` the medallion
already carries can override these when present; these are the local fallback.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    s = (s or "").lower()
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _digit_ratio(s: str) -> float:
    s = s or ""
    return (sum(ch.isdigit() for ch in s) / len(s)) if s else 0.0


def _max_consonant_run(s: str) -> int:
    vowels = set("aeiou")
    run = best = 0
    for ch in (s or "").lower():
        if ch.isalpha() and ch not in vowels:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def dga_score(label: str) -> float:
    """0..1 likelihood the label is algorithmically generated. High entropy, a
    high digit ratio and long consonant runs all push it up. Calibrated so normal
    brand words score low (~0.1–0.3) and random strings score high (~0.7+)."""
    s = (label or "").lower().replace("-", "")
    if len(s) < 4:
        return 0.0
    ent = shannon_entropy(s)
    ent_n = min(1.0, ent / 4.0)                 # ~4 bits ≈ very mixed
    digits = _digit_ratio(s)
    cons = min(1.0, _max_consonant_run(s) / 6.0)
    score = 0.55 * ent_n + 0.25 * digits + 0.20 * cons
    return round(min(1.0, score), 3)


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    a, b = a or "", b or ""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


def lookalike_distance(candidate_stem: str, brand_stem: str) -> int:
    """Edit distance between a candidate stem and a brand stem — a small non-zero
    distance (1–2) with the brand embedded is the classic typosquat signature."""
    return _levenshtein((candidate_stem or "").lower(), (brand_stem or "").lower())


def is_typosquat(candidate_stem: str, brand_stem: str) -> bool:
    d = lookalike_distance(candidate_stem, brand_stem)
    return 0 < d <= 2 and abs(len(candidate_stem) - len(brand_stem)) <= 2
