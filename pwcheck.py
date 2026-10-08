#!/usr/bin/env python3
"""
pwcheck - a small password strength & crackability checker.

Part of a starter security toolkit. It estimates how hard a password is to
crack (entropy + real-world crack times), flags weak/common passwords, and
optionally checks the Have I Been Pwned (HIBP) breach database using
k-anonymity, so the password itself is never sent over the network.

Concepts this also teaches (it is a learning artifact, not just a tool):
  * Shannon entropy as a measure of unpredictability
  * Why character-class pool size + length matter more than "complexity rules"
  * k-anonymity: querying a database without revealing the exact lookup key
  * Online vs. offline brute-force attack rates
"""

import argparse
import hashlib
import math
import shutil
import subprocess
import sys
import urllib.request
import urllib.error

# Attack rates (guesses per second) - how fast real adversaries can try.
RATES = [
    ("10/s       (offline, throttled / online w/ lockout)", 1e1),
    ("10,000/s   (slow single machine, throttled)",         1e4),
    ("1e10/s     (fast single GPU)",                        1e10),
    ("1e14/s     (GPU cluster, fast)",                      1e14),
]

# A starter list of the most common passwords. A real toolkit loads a large
# list (e.g. SecLists rockyou.txt, ~14M entries). We ship a small sample so the
# tool works out of the box with no dependencies.
COMMON = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "sunshine",
    "iloveyou", "princess", "admin", "letmein", "monkey", "login",
    "abc123", "passw0rd", "football", "welcome", "hello", "freedom",
    "qwerty123", "trustno1", "000000", "batman", "superman", "zaq12wsx",
]

# Entropy thresholds (bits) -> rating label.
ENTROPY_RATINGS = [
    (28, "WEAK"),
    (35, "FAIR"),
    (60, "GOOD"),
    (128, "STRONG"),
    (10**9, "EXCELLENT"),
]


def charset_pool(pw):
    """Size of the character pool the password draws from."""
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 33  # printable ASCII symbols
    return pool


def pool_label(pw):
    parts = []
    if any(c.islower() for c in pw):
        parts.append("lower")
    if any(c.isupper() for c in pw):
        parts.append("upper")
    if any(c.isdigit() for c in pw):
        parts.append("digits")
    if any(not c.isalnum() for c in pw):
        parts.append("symbols")
    return "+".join(parts) if parts else "(empty)"


def entropy_bits(pw):
    """Shannon-style entropy: length * log2(pool size)."""
    pool = charset_pool(pw)
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)


def rating_for(bits):
    for threshold, label in ENTROPY_RATINGS:
        if bits < threshold:
            return label
    return ENTROPY_RATINGS[-1][1]


def crack_times(bits):
    """[(label, seconds), ...] to crack on average."""
    guesses = 2 ** bits
    out = []
    for label, rate in RATES:
        out.append((label, guesses / 2 / rate))  # average case = half the space
    return out


def human_time(seconds):
    if seconds < 1:
        return "instant"
    units = [("century", 3.15576e9), ("year", 3.15576e7),
             ("month", 2.592e6), ("week", 604800),
             ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)]
    for name, secs in units:
        if seconds >= secs:
            val = seconds / secs
            if val < 10:
                return f"{val:.1f} {name}"
            return f"{int(val):,} {name}"
    return "< 1 second"


def is_common(pw):
    return pw.lower() in [c.lower() for c in COMMON]


def hibp_count(pw):
    """Check HIBP via k-anonymity. Returns breach count, or None if offline.

    Only the first 5 chars of the SHA-1 hash leave this machine; the full hash
    is compared locally. See https://www.troyhunt.com/have-i-been-pwned/
    """
    h = hashlib.sha1(pw.encode()).hexdigest()
    prefix, suffix = h[:5], h[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    body = None
    # Prefer urllib; on environments where Python can't verify TLS certificates
    # (e.g. some sandboxes / misconfigured CA bundles) fall back to curl, which
    # ships its own CA bundle. Both paths fetch the same public HIBP range API.
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            body = r.read().decode()
    except (urllib.error.URLError, OSError):
        if shutil.which("curl"):
            try:
                out = subprocess.run(
                    ["curl", "-sS", "--fail", url],
                    capture_output=True, timeout=15, text=True,
                )
                if out.returncode == 0:
                    body = out.stdout
            except (subprocess.SubprocessError, OSError):
                body = None

    if body is None:
        return None
    for line in body.splitlines():
        rng = line.strip()
        if rng[:len(suffix)].upper() == suffix.upper():
            return int(rng.split(":")[1])
    return 0


def suggest(pw):
    s = []
    if len(pw) < 12:
        s.append("Aim for 12+ characters - length beats complexity.")
    if not any(c.isupper() for c in pw):
        s.append("Mix in an uppercase letter.")
    if not any(c.isdigit() for c in pw):
        s.append("Add a digit.")
    if not any(not c.isalnum() for c in pw):
        s.append("Add a symbol (! @ # $ ...).")
    if is_common(pw):
        s.append("This is one of the most common passwords - change it.")
    if not s:
        s.append("Solid! A passphrase of 4+ random words (e.g. "
                 "'correct horse battery staple') is strong and memorable.")
    return s


def analyze(pw, check_breach=True):
    bits = entropy_bits(pw)
    report = {
        "length": len(pw),
        "pool": charset_pool(pw),
        "pool_label": pool_label(pw),
        "entropy": bits,
        "rating": rating_for(bits),
        "common": is_common(pw),
        "times": crack_times(bits),
    }
    if check_breach:
        report["breach_count"] = hibp_count(pw)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Password strength & crackability checker")
    ap.add_argument("password",
                    help="password to test (use '-' to read from stdin)")
    ap.add_argument("--no-breach", action="store_true",
                    help="skip the HIBP breach check (offline mode)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show all suggestions, not just the top one")
    args = ap.parse_args(argv)

    pw = args.password
    if pw == "-":
        pw = sys.stdin.read().strip()
    if not pw:
        print("No password provided.", file=sys.stderr)
        return 2

    r = analyze(pw, check_breach=not args.no_breach)

    print()
    print(f"  Length:  {r['length']} chars   Pool: {r['pool']} chars ({r['pool_label']})")
    print(f"  Entropy: {r['entropy']:.0f} bits   Rating: {r['rating']}")
    if r["common"]:
        print("  NOTE: matches a common-password list")
    print()
    print("  Time to crack (average case):")
    for label, secs in r["times"]:
        print(f"    {label:<42} {human_time(secs)}")
    print()

    if "breach_count" in r:
        bc = r["breach_count"]
        if bc is None:
            print("  Breach check (HIBP): skipped or offline")
        elif bc == 0:
            print("  Breach check (HIBP): not found in known breaches - good")
        else:
            print(f"  Breach check (HIBP): FOUND in {bc:,} known breaches - change it!")
    print()

    sugg = suggest(pw)
    if args.verbose:
        for s in sugg:
            print(f"  - {s}")
    else:
        print(f"  Top tip: {sugg[0]}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
