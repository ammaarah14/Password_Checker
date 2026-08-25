#!/usr/bin/env python3
"""
Password Strength + Breach Checker — CLI

Usage:
    python cli.py
    python cli.py --password "MyP@ssw0rd123"   (not recommended — visible in shell history)
    python cli.py --file passwords.txt          (batch-check, one password per line)
"""

import argparse
import getpass
import sys

from checker import (
    check_password_strength,
    check_breach,
    strength_label,
    crack_time_estimate,
)


def report(password: str):
    score, max_score, entropy, feedback = check_password_strength(password)
    label = strength_label(score, max_score)
    crack_time = crack_time_estimate(entropy)
    breach_count, error = check_breach(password)

    print(f"\nStrength: {label} ({score}/{max_score})")
    print(f"Estimated entropy: {entropy:.1f} bits")
    print(f"Rough offline crack time estimate: {crack_time}")

    if feedback:
        print("Suggestions:")
        for f in feedback:
            print(f"  - {f}")

    if error:
        print(f"Breach check: {error}")
    elif breach_count > 0:
        print(f"⚠️  Breach check: found in {breach_count:,} known breaches. Do not use this password.")
    else:
        print("✅ Breach check: not found in known breaches.")


def main():
    parser = argparse.ArgumentParser(description="Check password strength and breach history.")
    parser.add_argument("--password", help="Password to check (visible in shell history — for testing only)")
    parser.add_argument("--file", help="Path to a file of passwords, one per line, to batch-check")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file) as f:
                passwords = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"Could not read file: {e}", file=sys.stderr)
            sys.exit(1)

        for i, pw in enumerate(passwords, 1):
            print(f"\n{'=' * 40}\nPassword {i}/{len(passwords)}")
            report(pw)
        return

    password = args.password or getpass.getpass("Enter a password to check (input hidden): ")
    report(password)


if __name__ == "__main__":
    main()
