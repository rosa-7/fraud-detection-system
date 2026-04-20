# FraudShield Fusion

FraudShield Fusion is a Flask + SQLite digital fraud defense platform for phishing, scam, and online fraud awareness.

## Problem Statement
Online fraud and phishing attacks are increasing rapidly. This system helps users identify suspicious messages and URLs by analyzing content and assigning a risk score.

## Features
- Multi-engine detection for messages, URLs, email content, payment requests, passwords, and bulk text
- Privacy leak detection for Aadhaar, PAN, card-like numbers, bank details, OTP requests, and remote-access scams
- Local watchlist for suspicious domains, senders, numbers, UPI IDs, and keywords
- Incident reporting and CSV export
- Safe reply suggestions and next-step guidance
- Login lockout and CSRF protection
- Awareness, recovery, checklist, and resources pages
- Optional VirusTotal URL reputation check when `VIRUSTOTAL_API_KEY` is configured
- JSON API endpoint for scans

## Run locally
1. Create a virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file in the project folder and set `SECRET_KEY`.
4. Optionally set `VIRUSTOTAL_API_KEY` for external URL reputation checks.
5. Run: `python app.py`
6. Open the shown local URL in your browser.

The app loads the local `.env` file automatically, so no separate `python-dotenv` package is required.

## Demo account
- username: `admin`
- password: `Admin@1234`
