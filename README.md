# sec-toolkit

A small, dependency-free Python toolkit for getting a feel for security. Built
as a learning artifact first and a useful tool second.

## `pwcheck` — password strength & crackability checker

Estimates how hard a password is to crack, flags common passwords, and
(optionally) checks the Have I Been Pwned breach database using **k-anonymity**
— so the password itself never leaves your machine.

### Usage

```bash
python3 pwcheck.py "Sunshine1"
python3 pwcheck.py "P@ssw0rd" -v        # verbose: show all suggestions
echo "mypassword" | python3 pwcheck.py - --no-breach   # offline mode
```

### What it checks

| Check | What it tells you |
|---|---|
| **Entropy** | Unpredictability in bits (length × pool size) |
| **Crack time** | How long to brute-force at 4 real-world attack rates |
| **Common list** | Whether it's one of the most-guessed passwords |
| **HIBP breach** | Whether it appeared in a known data breach |
| **Suggestions** | Concrete ways to make it stronger |

### Concepts you'll learn from the code

- **Shannon entropy** as a measure of unpredictability
- Why **length + character pool size** matter more than "complexity rules"
- **k-anonymity**: querying a database without revealing the exact lookup key
  (only the first 5 hex chars of the SHA-1 hash are sent over the network)
- The difference between **online** and **offline** brute-force attack rates

### Notes

- No third-party dependencies — standard library only.
- The breach check needs network access; use `--no-breach` to run fully offline.
- The built-in common-password list is a small starter sample; a production
  toolkit would load a large list like SecLists `rockyou.txt` (~14M entries).
