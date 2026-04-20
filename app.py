from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from virustotal import scan_url_virustotal
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, unquote
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


def _load_env_file(env_path: Path) -> None:
    """Load key=value pairs from a local .env file without an extra dependency."""
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(Path(__file__).resolve().parent / '.env')

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / 'fraudshield.db'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
)


@dataclass
class Assessment:
    scan_kind: str
    label: str
    badge: str
    score: int
    threat_type: str
    reasons: List[str]
    advice: List[str]
    safe_reply: str
    checks: List[str]
    external: Optional[Dict[str, Any]] = None


# ----------------------------
# Database helpers
# ----------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def _table_columns(db: sqlite3.Connection, table: str) -> List[str]:
    rows = db.execute(f'PRAGMA table_info({table})').fetchall()
    return [row[1] for row in rows]


def _ensure_columns(db: sqlite3.Connection, table: str, columns: Dict[str, str]) -> None:
    existing = set(_table_columns(db, table))
    for name, ddl in columns.items():
        if name not in existing:
            db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}')


def init_db() -> None:
    db = get_db()
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_logins INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
        '''
    )
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_kind TEXT NOT NULL,
            input_text TEXT NOT NULL,
            score INTEGER NOT NULL,
            label TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            reasons TEXT NOT NULL,
            advice TEXT NOT NULL,
            safe_reply TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        '''
    )
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            report_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            subject TEXT NOT NULL,
            details TEXT NOT NULL,
            contact TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        '''
    )
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            item_value TEXT NOT NULL,
            notes TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        '''
    )

    _ensure_columns(db, 'users', {'failed_logins': 'INTEGER NOT NULL DEFAULT 0', 'locked_until': 'TEXT'})
    _ensure_columns(db, 'scans', {
        'scan_kind': "TEXT NOT NULL DEFAULT 'Message'",
        'score': 'INTEGER NOT NULL DEFAULT 0',
        'label': "TEXT NOT NULL DEFAULT 'Low Risk'",
        'threat_type': "TEXT NOT NULL DEFAULT 'General'",
        'reasons': "TEXT NOT NULL DEFAULT '[]'",
        'advice': "TEXT NOT NULL DEFAULT '[]'",
        'safe_reply': "TEXT NOT NULL DEFAULT ''",
    })
    _ensure_columns(db, 'reports', {'severity': "TEXT NOT NULL DEFAULT 'Medium'", 'status': "TEXT NOT NULL DEFAULT 'Open'"})
    _ensure_columns(db, 'watchlist', {'notes': 'TEXT', 'enabled': 'INTEGER NOT NULL DEFAULT 1'})

    if not db.execute('SELECT 1 FROM users WHERE username = ?', ('admin',)).fetchone():
        db.execute(
            'INSERT INTO users (username, password_hash, created_at, failed_logins, locked_until) VALUES (?, ?, ?, 0, NULL)',
            ('admin', generate_password_hash('Admin@1234'), utc_now()),
        )
    db.commit()
    db.close()


@app.before_request
def prepare_app() -> None:
    if not DATABASE.exists():
        init_db()
    if request.method == 'POST' and request.endpoint not in {'static'}:
        if request.endpoint not in {'login', 'register', 'api_scan'}:
            try:
                _validate_csrf()
            except PermissionError:
                abort(400)


# ----------------------------
# Auth and CSRF
# ----------------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


def csrf_token() -> str:
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


def _validate_csrf() -> None:
    sent = request.form.get('csrf_token', '')
    if not sent or sent != session.get('csrf_token'):
        flash('Your session expired. Please submit again.', 'error')
        raise PermissionError('Invalid CSRF token')


@app.context_processor
def inject_globals() -> Dict[str, Any]:
    return {'csrf_token': csrf_token(), 'session_user': session.get('username')}


def safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def load_json(text: str, default: Optional[Any] = None) -> Any:
    if not text:
        return default if default is not None else []
    try:
        return json.loads(text)
    except Exception:
        return default if default is not None else []


def normalize_text(text: str) -> str:
    return re.sub(r'\s+', ' ', (text or '').strip().lower())


# ----------------------------
# Detection patterns
# ----------------------------
MESSAGE_KEYWORDS = {
    'credential theft': ['otp', 'pin', 'cvv', 'password', 'passcode', 'secret code', 'verification code', 'bank login', 'card number'],
    'urgency pressure': ['urgent', 'immediately', 'within 10 minutes', 'today only', 'last chance', 'expires', 'expire now', 'account suspended'],
    'payment fraud': ['refund', 'collect request', 'approve', 'send money', 'transfer', 'upi', 'wallet', 'crypto', 'gift card', 'donation'],
    'impersonation': ['customer care', 'bank support', 'tax department', 'police', 'delivery agent', 'support team', 'admin'],
    'remote access': ['anydesk', 'teamviewer', 'screen share', 'remote access', 'install app', 'apk', 'download this app'],
    'deception': ['verify now', 'confirm identity', 'click below', 'account locked', 'your prize', 'you won', 'claim reward'],
}

URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly'}
RISKY_URL_WORDS = {'login', 'verify', 'secure', 'update', 'confirm', 'wallet', 'bank', 'reward', 'claim', 'invoice', 'tracking', 'payment', 'support', 'kyc'}
IMPLICIT_PAYMENT_WORDS = {'scan qr', 'qr code', 'collect', 'request money', 'approve request', 'accept request', 'refund', 'cashback', 'upi', 'wallet'}
EMAIL_HEADER_HINTS = {'from:', 'reply-to:', 'subject:', 'dkim', 'spf', 'dmarc'}
COMMON_PASSWORDS = {'password', 'admin123', 'qwerty', 'iloveyou', 'welcome123', '12345678', 'letmein', 'pass@123', 'admin@123', 'secret123'}
WATCHLIST_TYPES = {'keyword', 'domain', 'email', 'phone', 'upi'}

IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_RE = re.compile(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', re.I)
PHONE_RE = re.compile(r'\b(?:\+?91[-\s]?)?[6-9]\d{9}\b')
UPI_RE = re.compile(r'\b[a-z0-9._%+-]+@[a-z]{2,}\b', re.I)
AADHAAR_RE = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
PAN_RE = re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b', re.I)
IFSC_RE = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.I)
CARD_RE = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
OTP_RE = re.compile(r'\b\d{4,8}\b')


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r'\D', '', number)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _risk_band(score: int) -> Tuple[str, str]:
    if score >= 80:
        return 'Critical', 'danger'
    if score >= 60:
        return 'High Risk', 'danger'
    if score >= 35:
        return 'Suspicious', 'warning'
    return 'Low Risk', 'success'


def _threat_from_reasons(reasons: Sequence[str], scan_kind: str) -> str:
    joined = ' | '.join(reasons).lower()
    if 'password' in joined or 'credential' in joined:
        return 'Credential Theft'
    if 'phishing' in joined or 'domain' in joined or 'url' in joined or scan_kind == 'URL':
        return 'Phishing'
    if 'payment' in joined or 'upi' in joined or 'collect' in joined:
        return 'Payment Scam'
    if 'remote access' in joined or 'screen share' in joined:
        return 'Remote Access Scam'
    if 'privacy' in joined or 'aadhaar' in joined or 'pan' in joined or 'card' in joined:
        return 'Data Exposure'
    if 'email' in joined:
        return 'Email Scam'
    return 'General Scam'


def _safe_reply_for(threat_type: str, score: int) -> str:
    if score >= 80:
        return 'I will not continue this request. I will verify through the official app, website, or support number. Do not contact me again through this channel.'
    if threat_type == 'Payment Scam':
        return 'I will not approve the payment request. I will confirm the transaction using the official banking or wallet app.'
    if threat_type == 'Credential Theft':
        return 'I do not share OTPs, passwords, CVV, or PINs. Please use the official support channel.'
    if threat_type == 'Remote Access Scam':
        return 'I will not install remote-access software or share my screen. Please send the official support link only.'
    if threat_type == 'Data Exposure':
        return 'I will redact sensitive information and continue only through a verified secure channel.'
    return 'I will verify this request independently through an official source before taking any action.'


def _watchlist_matches(user_id: int, text: str, url_host: str = '') -> List[str]:
    db = get_db()
    rows = db.execute('SELECT item_type, item_value FROM watchlist WHERE user_id = ? AND enabled = 1', (user_id,)).fetchall()
    db.close()
    matches: List[str] = []
    text_norm = normalize_text(text)
    host_norm = (url_host or '').lower()
    for row in rows:
        item_type = row['item_type'].lower()
        value = normalize_text(row['item_value'])
        if not value:
            continue
        if item_type == 'domain' and host_norm:
            if value in host_norm or host_norm in value:
                matches.append(f'Domain watchlist hit: {row["item_value"]}')
        elif item_type == 'email':
            if value in text_norm:
                matches.append(f'Email watchlist hit: {row["item_value"]}')
        elif item_type == 'phone':
            if re.sub(r'\D', '', row['item_value']) in re.sub(r'\D', '', text_norm):
                matches.append(f'Phone watchlist hit: {row["item_value"]}')
        elif item_type == 'upi':
            if value in text_norm:
                matches.append(f'UPI watchlist hit: {row["item_value"]}')
        else:
            if value in text_norm:
                matches.append(f'Keyword watchlist hit: {row["item_value"]}')
    return matches


def _assessment(scan_kind: str, score: int, reasons: List[str], advice: List[str], checks: List[str], external: Optional[Dict[str, Any]] = None) -> Assessment:
    label, badge = _risk_band(min(score, 100))
    threat_type = _threat_from_reasons(reasons, scan_kind)
    safe_reply = _safe_reply_for(threat_type, score)
    if not reasons:
        reasons = ['No strong red flags were found.']
    if not advice:
        advice = ['Verify the sender using an official channel.', 'Do not share passwords, OTPs, or payment details.']
    return Assessment(scan_kind, label, badge, min(score, 100), threat_type, reasons, advice, safe_reply, checks, external)


def analyze_message(text: str, user_id: Optional[int] = None) -> Assessment:
    clean = normalize_text(text)
    if not clean:
        return _assessment('Message', 0, ['Enter a message or chat text to scan.'], ['Paste the suspicious text first.'], [])

    score = 0
    reasons: List[str] = []
    advice: List[str] = []
    checks: List[str] = []

    for category, keywords in MESSAGE_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in clean]
        if hits:
            checks.append(category)
            score += 11 + (3 * len(hits))
            reasons.append(f'Matches {category}: {", ".join(hits[:4])}')

    if 'http://' in clean:
        score += 15
        reasons.append('Contains insecure HTTP link')
        advice.append('Use trusted HTTPS sites only.')
        checks.append('insecure-link')

    if re.search(r'\b(verify|confirm|share|send|submit|provide|type)\b', clean) and re.search(r'\b(otp|pin|cvv|password|account|bank|upi|card)\b', clean):
        score += 22
        reasons.append('Requests credentials or payment details')
        advice.append('Never share OTPs, PINs, passwords, or CVV values.')
        checks.append('credential-request')

    if 'screen share' in clean or 'remote access' in clean or 'anydesk' in clean or 'teamviewer' in clean:
        score += 18
        reasons.append('Requests remote access or screen sharing')
        advice.append('Do not install remote access software from unverified sources.')
        checks.append('remote-access')

    if len(clean) > 500 and clean.count('click') >= 2:
        score += 8
        reasons.append('Repeated call-to-action language')
        checks.append('cta-overload')

    if clean.count('!') >= 3:
        score += 6
        reasons.append('Excessive urgency punctuation')
        checks.append('urgency-markers')

    privacy_hits = []
    if AADHAAR_RE.search(text or ''):
        privacy_hits.append('Aadhaar-like number detected')
    if PAN_RE.search(text or ''):
        privacy_hits.append('PAN-like number detected')
    if IFSC_RE.search(text or ''):
        privacy_hits.append('IFSC-like code detected')
    if CARD_RE.search(text or ''):
        for card in CARD_RE.findall(text or ''):
            if luhn_ok(card):
                privacy_hits.append('Card-like number passes Luhn check')
                break
    if privacy_hits:
        score += 12 + (4 * len(privacy_hits))
        reasons.extend(privacy_hits)
        advice.append('Redact sensitive personal and banking information before sharing.')
        checks.append('privacy-exposure')

    if OTP_RE.search(clean):
        score += 4
        reasons.append('Contains OTP-like numeric sequence')
        checks.append('otp-pattern')

    if user_id is not None:
        watch_hits = _watchlist_matches(user_id, text)
        if watch_hits:
            score += 20 + (3 * len(watch_hits))
            reasons.extend(watch_hits)
            advice.append('This item matches your local watchlist. Treat it as high risk.')
            checks.append('watchlist-hit')

    if not advice:
        advice = [
            'Check the sender through a trusted channel.',
            'Avoid opening links or attachments from unknown sources.',
            'Do not share OTPs, passwords, or payment details.',
        ]

    return _assessment('Message', score, reasons, advice, checks)


def analyze_url(raw_url: str, user_id: Optional[int] = None) -> Assessment:
    raw = (raw_url or '').strip()
    if not raw:
        return _assessment('URL', 0, ['Enter a URL to scan.'], ['Paste the suspicious link first.'], [])

    if '://' not in raw:
        raw = 'https://' + raw

    parsed = urlparse(raw)
    host = (parsed.hostname or '').lower()
    path = unquote(parsed.path or '')
    query = unquote(parsed.query or '')
    full = raw.lower()

    score = 0
    reasons: List[str] = []
    advice: List[str] = []
    checks: List[str] = []
    external: Optional[Dict[str, Any]] = None

    if parsed.scheme != 'https':
        score += 16
        reasons.append('URL does not use HTTPS')
        advice.append('Use secure HTTPS websites whenever possible.')
        checks.append('insecure-scheme')

    if not host:
        score += 20
        reasons.append('Unable to parse host')
        checks.append('parse-failure')
    else:
        if IPV4_RE.search(host):
            score += 25
            reasons.append('Uses an IP address instead of a domain name')
            checks.append('ip-host')
        if host.startswith('xn--') or '.xn--' in host:
            score += 24
            reasons.append('Possible punycode or lookalike domain')
            checks.append('punycode')
        if host.count('.') >= 3:
            score += 9
            reasons.append('Has unusually deep subdomains')
            checks.append('deep-subdomains')
        if len(host) > 30:
            score += 7
            reasons.append('Hostname is unusually long')
            checks.append('long-host')
        if host.count('-') >= 3:
            score += 7
            reasons.append('Hostname contains many hyphens')
            checks.append('hyphenated-host')
        if host in URL_SHORTENERS:
            score += 15
            reasons.append('Uses a link-shortening service')
            checks.append('shortener')

    for word in RISKY_URL_WORDS:
        if word in full or word in path.lower() or word in query.lower():
            score += 5
            reasons.append(f'Contains risky URL term: {word}')
            checks.append(f'url-word:{word}')

    if any(k in (path + ' ' + query).lower() for k in ['password', 'otp', 'login', 'bank', 'upi', 'kyc', 'refund', 'invoice', 'payment', 'verify']):
        score += 10
        reasons.append('Path or query appears to target credentials or payments')
        checks.append('targeting-credentials')

    if '%' in query and len(query) > 30:
        score += 5
        reasons.append('Encoded or long query may hide redirect logic')
        checks.append('encoded-query')

    if '@' in parsed.netloc:
        score += 20
        reasons.append('Contains userinfo in the URL')
        checks.append('userinfo')

    vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()
    if vt_api_key:
        external = scan_url_virustotal(raw)
        if external.get('ok'):
            malicious = int(external.get('malicious', 0) or 0)
            suspicious = int(external.get('suspicious', 0) or 0)
            if malicious > 0:
                score += 35
                reasons.append(f"VirusTotal flagged {malicious} engine(s) as malicious")
                advice.append('Do not open this link. Verify the sender through an official channel.')
                checks.append('virustotal-malicious')
            elif suspicious > 0:
                score += 18
                reasons.append(f"VirusTotal flagged {suspicious} engine(s) as suspicious")
                checks.append('virustotal-suspicious')
            else:
                checks.append('virustotal-clean')
        else:
            checks.append('virustotal-error')
            reasons.append(f"VirusTotal unavailable: {external.get('error', 'unknown error')}")

    if user_id is not None:
        watch_hits = _watchlist_matches(user_id, raw, host)
        if watch_hits:
            score += 20 + (2 * len(watch_hits))
            reasons.extend(watch_hits)
            advice.append('This URL matches your watchlist. Do not open it.')
            checks.append('watchlist-hit')

    if not advice:
        advice = [
            'Inspect the full domain before clicking.',
            'Open only from trusted sources.',
            'Do not enter credentials from a message link.',
        ]

    return _assessment('URL', score, reasons, advice, checks, external=external)


def analyze_payment(text: str, user_id: Optional[int] = None) -> Assessment:
    clean = normalize_text(text)
    if not clean:
        return _assessment('Payment', 0, ['Enter payment text, UPI ID, or request details.'], ['Paste the suspicious payment content first.'], [])

    score = 0
    reasons: List[str] = []
    advice: List[str] = []
    checks: List[str] = []

    if UPI_RE.search(clean):
        score += 18
        reasons.append('Looks like a UPI handle or payment identifier')
        checks.append('upi-pattern')
    if PHONE_RE.search(clean):
        score += 12
        reasons.append('Contains a mobile-number pattern')
        checks.append('phone-pattern')

    if any(k in clean for k in IMPLICIT_PAYMENT_WORDS):
        score += 17
        reasons.append('Contains common payment-scam language')
        checks.append('payment-language')

    if any(k in clean for k in ['otp', 'pin', 'cvv', 'qr', 'scan', 'remote', 'screen share']):
        score += 14
        reasons.append('Requests sensitive payment verification or remote help')
        checks.append('verification-abuse')

    if any(k in clean for k in ['call me', 'whatsapp', 'telegram', 'outside the app']):
        score += 8
        reasons.append('Moves the conversation away from the official app')
        checks.append('off-platform')

    if user_id is not None:
        watch_hits = _watchlist_matches(user_id, text)
        if watch_hits:
            score += 18 + (2 * len(watch_hits))
            reasons.extend(watch_hits)
            advice.append('Payment item found in your watchlist. Treat as suspicious.')
            checks.append('watchlist-hit')

    if not advice:
        advice = [
            'Confirm the requester using a trusted official channel.',
            'Reject QR scans or collect requests from unknown senders.',
            'Report suspicious payment requests to your bank or wallet provider.',
        ]

    return _assessment('Payment', score, reasons, advice, checks)


def analyze_email(text: str, user_id: Optional[int] = None) -> Assessment:
    clean = text or ''
    lower = normalize_text(clean)
    if not lower:
        return _assessment('Email', 0, ['Paste the email body or header lines to scan.'], ['Include sender, reply-to, subject, and links.'], [])

    score = 0
    reasons: List[str] = []
    advice: List[str] = []
    checks: List[str] = []

    header_lines = [line.strip() for line in clean.splitlines() if ':' in line]
    header_map: Dict[str, List[str]] = defaultdict(list)
    for line in header_lines:
        name, value = line.split(':', 1)
        header_map[name.strip().lower()].append(value.strip())

    if 'reply-to' in header_map and 'from' in header_map:
        reply = ' '.join(header_map['reply-to'])
        frm = ' '.join(header_map['from'])
        if reply and frm and reply not in frm:
            score += 16
            reasons.append('Reply-To differs from the visible From field')
            checks.append('reply-to-mismatch')

    if 'subject' in header_map and any(term in ' '.join(header_map['subject']).lower() for term in ['urgent', 'verify', 'suspended', 'payment failed', 'action required']):
        score += 8
        reasons.append('Subject uses urgent account-related wording')
        checks.append('urgent-subject')

    if any(h in lower for h in EMAIL_HEADER_HINTS):
        checks.append('header-like')

    if any(term in lower for term in ['unsubscribe', 'confirm your account', 'verify now', 'reset password', 'password expired']):
        score += 10
        reasons.append('Contains suspicious account action wording')
        checks.append('account-action')

    body_assessment = analyze_message(clean, user_id=user_id)
    score += body_assessment.score // 2
    reasons.extend(body_assessment.reasons[:4])
    advice.extend(body_assessment.advice[:2])
    checks.extend(body_assessment.checks[:3])

    if not advice:
        advice = [
            'Compare sender, reply-to, and domain carefully.',
            'Avoid clicking links in unsolicited emails.',
            'Verify through official support channels instead of replying directly.',
        ]

    return _assessment('Email', score, reasons, advice, checks)


def analyze_password(password: str) -> Assessment:
    pw = password or ''
    if not pw:
        return _assessment('Password', 0, ['Enter a password to score strength.'], ['Use a long, unique password with mixed characters.'], [])

    score = 0
    reasons: List[str] = []
    advice: List[str] = []
    checks: List[str] = []

    length = len(pw)
    if length < 8:
        score += 35
        reasons.append('Password is too short')
        advice.append('Use at least 12 characters.')
    elif length < 12:
        score += 18
        reasons.append('Password length is moderate')
        advice.append('Longer passwords are harder to guess.')
    else:
        score -= 8

    classes = sum(bool(re.search(pattern, pw)) for pattern in [r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'])
    if classes >= 3:
        score -= 10
    else:
        score += 12
        reasons.append('Password uses limited character variety')
        advice.append('Mix uppercase, lowercase, numbers, and symbols.')

    if pw.lower() in COMMON_PASSWORDS or any(word in pw.lower() for word in COMMON_PASSWORDS):
        score += 30
        reasons.append('Password resembles a common weak password')
        checks.append('common-password')

    if re.search(r'(.)\1\1', pw):
        score += 10
        reasons.append('Contains repeated characters')
        checks.append('repetition')
    if re.search(r'(1234|abcd|qwerty|9876)', pw.lower()):
        score += 15
        reasons.append('Contains a predictable sequence')
        checks.append('sequence')

    if not re.search(r'[^A-Za-z0-9]', pw):
        score += 10
        reasons.append('No special characters detected')
    if not re.search(r'\d', pw):
        score += 8
        reasons.append('No digits detected')

    if not advice:
        advice = [
            'Use a password manager to generate unique passwords.',
            'Enable multi-factor authentication for critical accounts.',
        ]

    return _assessment('Password', max(score, 0), reasons, advice, checks)


def analyze_bulk(text: str, user_id: Optional[int] = None) -> List[Assessment]:
    lines = [line.strip() for line in (text or '').splitlines() if line.strip()]
    results: List[Assessment] = []
    for line in lines:
        if line.lower().startswith(('http://', 'https://', 'www.')) or re.search(r'\b[a-z0-9.-]+\.[a-z]{2,}\b', line, re.I):
            result = analyze_url(line, user_id=user_id)
        elif UPI_RE.search(line) or PHONE_RE.search(line) or any(k in normalize_text(line) for k in IMPLICIT_PAYMENT_WORDS):
            result = analyze_payment(line, user_id=user_id)
        elif EMAIL_RE.search(line) or any(h in normalize_text(line) for h in EMAIL_HEADER_HINTS):
            result = analyze_email(line, user_id=user_id)
        else:
            result = analyze_message(line, user_id=user_id)
        results.append(result)
    return results


def _result_to_dict(result: Assessment) -> Dict[str, Any]:
    return asdict(result)


def _save_scan(user_id: int, scan_kind: str, input_text: str, result: Assessment) -> None:
    db = get_db()
    db.execute(
        '''
        INSERT INTO scans (user_id, scan_kind, input_text, score, label, threat_type, reasons, advice, safe_reply, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            user_id,
            scan_kind,
            input_text,
            result.score,
            result.label,
            result.threat_type,
            safe_json(result.reasons),
            safe_json(result.advice),
            result.safe_reply,
            utc_now(),
        ),
    )
    db.commit()
    db.close()


def _save_report(user_id: int, report_type: str, severity: str, subject: str, details: str, contact: str) -> None:
    db = get_db()
    db.execute(
        '''
        INSERT INTO reports (user_id, report_type, severity, status, subject, details, contact, created_at)
        VALUES (?, ?, ?, 'Open', ?, ?, ?, ?)
        ''',
        (user_id, report_type, severity, subject, details, contact, utc_now()),
    )
    db.commit()
    db.close()


def _save_watchlist(user_id: int, item_type: str, item_value: str, notes: str) -> None:
    db = get_db()
    db.execute(
        'INSERT INTO watchlist (user_id, item_type, item_value, notes, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)',
        (user_id, item_type, item_value, notes, utc_now()),
    )
    db.commit()
    db.close()


def _summary(db: sqlite3.Connection, user_id: int) -> Dict[str, Any]:
    counts = db.execute(
        '''
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN score >= 80 THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN score >= 60 AND score < 80 THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN score >= 35 AND score < 60 THEN 1 ELSE 0 END) AS suspicious,
            SUM(CASE WHEN score < 35 THEN 1 ELSE 0 END) AS low
        FROM scans WHERE user_id = ?
        ''',
        (user_id,),
    ).fetchone()
    watchlist_total = db.execute('SELECT COUNT(*) AS total FROM watchlist WHERE user_id = ?', (user_id,)).fetchone()['total']
    report_total = db.execute('SELECT COUNT(*) AS total FROM reports WHERE user_id = ?', (user_id,)).fetchone()['total']
    return {**dict(counts), 'watchlist_total': watchlist_total, 'report_total': report_total}


# ----------------------------
# Routes
# ----------------------------
@app.route('/')
def home():
    return redirect(url_for('dashboard' if 'user_id' in session else 'login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        db = get_db()
        exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if exists:
            db.close()
            flash('Username already exists.', 'error')
            return render_template('register.html')

        db.execute(
            'INSERT INTO users (username, password_hash, created_at, failed_logins, locked_until) VALUES (?, ?, ?, 0, NULL)',
            (username, generate_password_hash(password), utc_now()),
        )
        db.commit()
        db.close()
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and user['locked_until']:
            try:
                locked_until = datetime.strptime(user['locked_until'], '%Y-%m-%d %H:%M:%S UTC')
            except Exception:
                locked_until = None
            if locked_until and datetime.now(timezone.utc) < locked_until.replace(tzinfo=timezone.utc):
                db.close()
                flash('This account is temporarily locked due to repeated failed logins.', 'error')
                return render_template('login.html')

        if user and check_password_hash(user['password_hash'], password):
            db.execute('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?', (user['id'],))
            db.commit()
            db.close()
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['csrf_token'] = secrets.token_urlsafe(32)
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))

        if user:
            failed = int(user['failed_logins'] or 0) + 1
            locked_until = None
            if failed >= 5:
                locked_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S UTC')
            db.execute('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?', (failed, locked_until, user['id']))
            db.commit()
        db.close()
        flash('Invalid username or password.', 'error')
        return render_template('login.html')

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    summary = _summary(db, session['user_id'])
    stats = {
        'total_scans': db.execute('SELECT COUNT(*) AS total FROM scans WHERE user_id = ?', (session['user_id'],)).fetchone()['total'],
        'total_reports': summary['report_total'],
        'total_watchlist': summary['watchlist_total'],
        'critical_scans': summary.get('critical', 0) or 0,
        'high_scans': summary.get('high', 0) or 0,
    }

    recent_scans = db.execute(
        '''
        SELECT scan_kind, input_text, label, score, threat_type, created_at
        FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 6
        ''',
        (session['user_id'],),
    ).fetchall()
    recent_reports = db.execute(
        '''
        SELECT report_type, severity, status, subject, created_at
        FROM reports WHERE user_id = ? ORDER BY id DESC LIMIT 6
        ''',
        (session['user_id'],),
    ).fetchall()
    threat_rows = db.execute(
        '''
        SELECT threat_type, COUNT(*) AS total
        FROM scans WHERE user_id = ? GROUP BY threat_type ORDER BY total DESC, threat_type ASC
        ''',
        (session['user_id'],),
    ).fetchall()
    watchlist_rows = db.execute(
        'SELECT item_type, item_value, notes, enabled, created_at FROM watchlist WHERE user_id = ? ORDER BY id DESC LIMIT 5',
        (session['user_id'],),
    ).fetchall()
    db.close()
    return render_template('dashboard.html', stats=stats, summary=summary, recent_scans=recent_scans, recent_reports=recent_reports, threat_rows=threat_rows, watchlist_rows=watchlist_rows)


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    active_result: Optional[Dict[str, Any]] = None
    active_title = 'No scan run yet'
    bulk_results: List[Dict[str, Any]] = []
    query = request.args.get('q', '').strip()

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'message':
            text = request.form.get('message_text', '').strip()
            result = analyze_message(text, user_id=session['user_id'])
            _save_scan(session['user_id'], 'Message', text, result)
            active_result = _result_to_dict(result)
            active_title = 'Message scan'
            flash('Message analysis completed.', 'success')
        elif action == 'url':
            text = request.form.get('url_text', '').strip()
            result = analyze_url(text, user_id=session['user_id'])
            _save_scan(session['user_id'], 'URL', text, result)
            active_result = _result_to_dict(result)
            active_title = 'URL scan'
            flash('URL analysis completed.', 'success')
        elif action == 'payment':
            text = request.form.get('payment_text', '').strip()
            result = analyze_payment(text, user_id=session['user_id'])
            _save_scan(session['user_id'], 'Payment', text, result)
            active_result = _result_to_dict(result)
            active_title = 'Payment scan'
            flash('Payment analysis completed.', 'success')
        elif action == 'email':
            text = request.form.get('email_text', '').strip()
            result = analyze_email(text, user_id=session['user_id'])
            _save_scan(session['user_id'], 'Email', text, result)
            active_result = _result_to_dict(result)
            active_title = 'Email scan'
            flash('Email analysis completed.', 'success')

    db = get_db()
    sql = 'SELECT scan_kind, input_text, score, label, threat_type, created_at FROM scans WHERE user_id = ?'
    params: List[Any] = [session['user_id']]
    if query:
        sql += ' AND (input_text LIKE ? OR scan_kind LIKE ? OR threat_type LIKE ? OR label LIKE ?)'
        like = f'%{query}%'
        params.extend([like, like, like, like])
    sql += ' ORDER BY id DESC LIMIT 20'
    history = db.execute(sql, params).fetchall()
    db.close()

    return render_template(
        'scan.html',
        active_result=active_result,
        active_title=active_title,
        bulk_results=bulk_results,
        history=history,
        query=query,
    )


@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    payload = request.get_json(silent=True) or {}
    scan_type = (payload.get('scan_type') or 'message').lower()
    text = str(payload.get('text') or '')
    if scan_type == 'url':
        result = analyze_url(text, user_id=session['user_id'])
    elif scan_type == 'payment':
        result = analyze_payment(text, user_id=session['user_id'])
    elif scan_type == 'email':
        result = analyze_email(text, user_id=session['user_id'])
    elif scan_type == 'password':
        result = analyze_password(text)
    elif scan_type == 'bulk':
        result = {'items': [_result_to_dict(r) for r in analyze_bulk(text, user_id=session['user_id'])]}
        return jsonify(result)
    else:
        result = analyze_message(text, user_id=session['user_id'])
    return jsonify(_result_to_dict(result))


@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    if request.method == 'POST':
        report_type = request.form.get('report_type', '').strip()
        severity = request.form.get('severity', 'Medium').strip() or 'Medium'
        subject = request.form.get('subject', '').strip()
        details = request.form.get('details', '').strip()
        contact = request.form.get('contact', '').strip()
        if not report_type or not subject or not details:
            flash('Please fill in all required fields.', 'error')
        else:
            _save_report(session['user_id'], report_type, severity, subject, details, contact)
            flash('Incident report submitted successfully.', 'success')
            return redirect(url_for('reports'))

    db = get_db()
    rows = db.execute(
        '''
        SELECT report_type, severity, status, subject, details, contact, created_at
        FROM reports WHERE user_id = ? ORDER BY id DESC LIMIT 20
        ''',
        (session['user_id'],),
    ).fetchall()
    db.close()
    return render_template('reports.html', rows=rows)


@app.route('/reports/export')
@login_required
def reports_export():
    db = get_db()
    rows = db.execute(
        'SELECT report_type, severity, status, subject, details, contact, created_at FROM reports WHERE user_id = ? ORDER BY id DESC',
        (session['user_id'],),
    ).fetchall()
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['report_type', 'severity', 'status', 'subject', 'details', 'contact', 'created_at'])
    for row in rows:
        writer.writerow([row['report_type'], row['severity'], row['status'], row['subject'], row['details'], row['contact'], row['created_at']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name='fraudshield_reports.csv')


@app.route('/scans/export')
@login_required
def scans_export():
    db = get_db()
    rows = db.execute(
        'SELECT scan_kind, input_text, score, label, threat_type, reasons, advice, safe_reply, created_at FROM scans WHERE user_id = ? ORDER BY id DESC',
        (session['user_id'],),
    ).fetchall()
    db.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['scan_kind', 'input_text', 'score', 'label', 'threat_type', 'reasons', 'advice', 'safe_reply', 'created_at'])
    for row in rows:
        writer.writerow([row['scan_kind'], row['input_text'], row['score'], row['label'], row['threat_type'], row['reasons'], row['advice'], row['safe_reply'], row['created_at']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name='fraudshield_scans.csv')


@app.route('/watchlist', methods=['GET', 'POST'])
@login_required
def watchlist():
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'add':
            item_type = request.form.get('item_type', '').strip().lower()
            item_value = request.form.get('item_value', '').strip()
            notes = request.form.get('notes', '').strip()
            if item_type not in WATCHLIST_TYPES or not item_value:
                flash('Please select a valid watchlist type and enter a value.', 'error')
            else:
                _save_watchlist(session['user_id'], item_type, item_value, notes)
                flash('Watchlist item added.', 'success')
                return redirect(url_for('watchlist'))
        elif action in {'toggle', 'delete'}:
            item_id = request.form.get('item_id', '').strip()
            if not item_id.isdigit():
                flash('Invalid item selected.', 'error')
            else:
                db = get_db()
                row = db.execute('SELECT * FROM watchlist WHERE id = ? AND user_id = ?', (int(item_id), session['user_id'])).fetchone()
                if row:
                    if action == 'toggle':
                        db.execute('UPDATE watchlist SET enabled = ? WHERE id = ?', (0 if row['enabled'] else 1, row['id']))
                        db.commit()
                        flash('Watchlist item updated.', 'success')
                    else:
                        db.execute('DELETE FROM watchlist WHERE id = ?', (row['id'],))
                        db.commit()
                        flash('Watchlist item removed.', 'success')
                db.close()
                return redirect(url_for('watchlist'))

    db = get_db()
    rows = db.execute('SELECT * FROM watchlist WHERE user_id = ? ORDER BY id DESC', (session['user_id'],)).fetchall()
    db.close()
    return render_template('watchlist.html', rows=rows)


@app.route('/awareness')
@login_required
def awareness():
    return render_template('awareness.html')


@app.route('/recovery')
@login_required
def recovery():
    return render_template('recovery.html')


@app.route('/checklist')
@login_required
def checklist():
    return render_template('checklist.html')


@app.route('/resources')
@login_required
def resources():
    return render_template('resources.html')


@app.route('/health')
def health():
    return {'ok': True, 'name': 'FraudShield Plus'}


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
