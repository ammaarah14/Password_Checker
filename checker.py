"""
Core password strength + breach-checking logic.
Shared by both the CLI tool (cli.py) and the web app (app.py).
"""

import re
import hashlib
import math
import requests


def check_password_strength(password: str):
    """Returns (score, max_score, entropy_bits, feedback_list)."""
    score = 0
    max_score = 6
    feedback = []

    # Length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short — use at least 12 characters")

    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    if has_lower:
        score += 1
    else:
        feedback.append("Add a lowercase letter")

    if has_upper:
        score += 1
    else:
        feedback.append("Add an uppercase letter")

    if has_digit:
        score += 1
    else:
        feedback.append("Add a number")

    if has_symbol:
        score += 1
    else:
        feedback.append("Add a special character")

    # Common weak patterns
    common_patterns = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome']
    if any(p in password.lower() for p in common_patterns):
        score = max(0, score - 3)
        feedback.append("Contains a common weak pattern")

    score = max(0, min(score, max_score))

    # Rough entropy estimate (bits)
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32
    entropy = len(password) * math.log2(charset_size) if charset_size and password else 0

    return score, max_score, entropy, feedback


def check_breach(password: str):
    """
    Checks the password against the HaveIBeenPwned API using k-anonymity:
    only the first 5 chars of the SHA-1 hash are sent, never the password
    or full hash itself.
    Returns (breach_count, error_message).
    """
    if not password:
        return 0, None

    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=10,
        )
    except requests.RequestException as e:
        return None, f"Error contacting breach database: {e}"

    if response.status_code != 200:
        return None, f"Error contacting breach database (status {response.status_code})"

    for line in response.text.splitlines():
        h, count = line.split(':')
        if h == suffix:
            return int(count), None

    return 0, None


def strength_label(score: int, max_score: int) -> str:
    pct = score / max_score
    if pct >= 0.85:
        return "Strong"
    elif pct >= 0.5:
        return "Moderate"
    else:
        return "Weak"


def crack_time_estimate(entropy_bits: float) -> str:
    """Very rough offline-attack crack time estimate, assuming 10 billion guesses/sec."""
    if entropy_bits <= 0:
        return "instantly"
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10
    units = [
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            return f"~{value:,.1f} {name}"
    return "instantly"
