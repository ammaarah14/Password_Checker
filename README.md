# Vault — Password Strength & Breach Checker

A small security tool available two ways: a command-line script and a local
web app. Both share the same core logic in `checker.py`.

## What it does

1. **Strength scoring** — checks length, character variety, and common weak
   patterns; estimates entropy in bits and a rough offline crack-time.
2. **Breach checking** — queries the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords)
   Pwned Passwords API using **k-anonymity**: your password is hashed with
   SHA-1 locally, and only the **first 5 characters** of that hash are sent
   to the API. The API returns every hash suffix matching that prefix
   (usually several hundred), and the match is found locally. Your full
   password and full hash never leave your machine.

## Setup

```bash
pip install -r requirements.txt
```

## Run the CLI

```bash
python cli.py                          # interactive, hidden input
python cli.py --password "test123"     # inline (visible in shell history — testing only)
python cli.py --file passwords.txt     # batch check, one password per line
```

## Run the web app

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Project structure

```
password_checker/
├── checker.py      # shared strength + breach logic
├── cli.py          # command-line tool
├── app.py          # Flask web server
├── templates/
│   └── index.html  # web UI
├── requirements.txt
└── README.md
```

## Why this is a reasonable security demo

- **K-anonymity API design** is a real privacy-preserving pattern used
  outside password checking too (it's worth being able to explain in an
  interview).
- **Nothing is logged or stored** — the app processes each password
  in-memory per request and discards it.
- The web version keeps the breach check **server-side** rather than calling
  the HIBP API directly from the browser, which avoids exposing lookups to
  client-side network inspection and sidesteps CORS issues.

## Notes / limitations

- The strength scoring here is a simple heuristic (length + character sets +
  a small deny-list), not a full implementation of something like
  [zxcvbn](https://github.com/dropbox/zxcvbn) — a good "next step" if you
  want to extend this project.
- The crack-time estimate assumes a fixed guess rate (10 billion/sec) for
  an offline attack against a fast, unsalted hash — it's illustrative, not
  a precise prediction, since real crack times depend heavily on how the
  password is stored (e.g. bcrypt/argon2 vs plain SHA-1).
