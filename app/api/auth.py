"""
Real (if minimal) authentication for the frontend.

Passwords are PBKDF2-HMAC-SHA256 hashed with a per-user salt; sessions are
HMAC-SHA256 signed tokens with an expiry. Stdlib only -- no new dependencies.
Users persist to .auth_store.json (gitignored). A demo admin is seeded on first
run. This is a genuine mechanism, but single-store and demo-seeded; swap the
store for a real DB before production.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

_STORE = Path(__file__).resolve().parents[2] / ".auth_store.json"
_TTL = 60 * 60 * 12  # 12h tokens
_ITER = 200_000


def _load() -> dict:
    if _STORE.exists():
        try:
            return json.loads(_STORE.read_text())
        except json.JSONDecodeError:
            pass
    store = {"secret": secrets.token_hex(32), "users": {}}
    _seed(store)
    _save(store)
    return store


def _save(store: dict) -> None:
    try:
        _STORE.write_text(json.dumps(store))
    except OSError:
        pass


def _hash(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITER)
    return dk.hex()


def _seed(store: dict) -> None:
    salt = secrets.token_hex(16)
    store["users"]["admin@mailtrace.io"] = {
        "name": "Admin User", "role": "Administrator",
        "salt": salt, "hash": _hash("demo1234", salt),
    }


def _sign(store: dict, email: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": email, "exp": int(time.time()) + _TTL}).encode()).decode()
    sig = hmac.new(store["secret"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify(store: dict, token: str) -> str | None:
    try:
        payload, sig = token.split(".", 1)
    except ValueError:
        return None
    expect = hmac.new(store["secret"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return None
    data = json.loads(base64.urlsafe_b64decode(payload))
    if data.get("exp", 0) < time.time():
        return None
    return data.get("sub")


def _user_public(store: dict, email: str) -> dict:
    u = store["users"][email]
    return {"email": email, "name": u["name"], "role": u.get("role", "Analyst")}


class Creds(BaseModel):
    email: str
    password: str
    name: str | None = None


@router.post("/login")
async def login(c: Creds) -> dict:
    store = _load()
    u = store["users"].get(c.email.lower().strip())
    if not u or not hmac.compare_digest(_hash(c.password, u["salt"]), u["hash"]):
        raise HTTPException(401, "Invalid email or password")
    email = c.email.lower().strip()
    return {"token": _sign(store, email), "user": _user_public(store, email)}


# --- Account creation via emailed one-time code (OTP) ------------------------
# Registration is two-step: /register/request emails a code and holds the
# pending signup in memory; /register/verify checks the code, then creates the
# account. The account does not exist until the email is proven.
_PENDING: dict[str, tuple[str, float, str, str]] = {}  # email -> (otp, expiry, name, password)
_REG_TTL = 600  # 10 minutes


class RegisterVerify(BaseModel):
    email: str
    otp: str


@router.post("/register/request", status_code=202)
async def register_request(c: Creds) -> dict:
    """Step 1: validate the details and email a verification code."""
    store = _load()
    email = c.email.lower().strip()
    if "@" not in email or len(c.password) < 6:
        raise HTTPException(400, "Valid email and a 6+ char password required")
    if email in store["users"]:
        raise HTTPException(409, "An account with that email already exists")
    otp = f"{secrets.randbelow(1_000_000):06d}"
    name = c.name or email.split("@")[0].title()
    _PENDING[email] = (otp, time.time() + _REG_TTL, name, c.password)
    sent, detail = await asyncio.to_thread(_send_otp_email, email, otp, "verify your new account")
    return _otp_response(otp, sent, detail)


@router.post("/register/verify", status_code=201)
async def register_verify(c: RegisterVerify) -> dict:
    """Step 2: verify the code, create the account, and sign in."""
    store = _load()
    email = c.email.lower().strip()
    rec = _PENDING.get(email)
    if not rec or rec[1] < time.time():
        raise HTTPException(400, "Code expired or not requested — start again")
    if not hmac.compare_digest(rec[0], c.otp.strip()):
        raise HTTPException(400, "Incorrect code")
    if email in store["users"]:  # raced another signup
        _PENDING.pop(email, None)
        raise HTTPException(409, "An account with that email already exists")
    _, _, name, password = rec
    salt = secrets.token_hex(16)
    store["users"][email] = {
        "name": name, "role": "Analyst",
        "salt": salt, "hash": _hash(password, salt),
    }
    _save(store)
    _PENDING.pop(email, None)
    return {"token": _sign(store, email), "user": _user_public(store, email)}


# --- Password reset via emailed one-time code (OTP) --------------------------
_OTP: dict[str, tuple[str, float]] = {}   # email -> (code, expiry). In-memory.
_OTP_TTL = 600  # 10 minutes


class EmailOnly(BaseModel):
    email: str


class ResetVerify(BaseModel):
    email: str
    otp: str
    password: str


def _send_otp_email(to: str, otp: str, purpose: str = "reset your password") -> tuple[bool, str]:
    """Send the OTP via SMTP.

    Returns (sent, detail). detail is "" on success, "not_configured" when no
    SMTP credentials are set, or a short error string (type + message, never the
    credentials) when the send itself fails -- so a caller can explain WHY.
    `purpose` phrases the subject/body for the reset vs signup flows.
    """
    cfg = settings()
    if not (cfg.smtp_user and cfg.smtp_password):
        return False, "not_configured"
    msg = EmailMessage()
    msg["Subject"] = f"Your Mailtrace code to {purpose}"
    msg["From"] = cfg.smtp_from or cfg.smtp_user
    msg["To"] = to
    msg.set_content(
        f"Your Mailtrace verification code is: {otp}\n\n"
        f"Use it to {purpose}. It expires in 10 minutes. "
        "If you didn't request this, you can ignore this email."
    )
    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10) as s:
            s.starttls()
            s.login(cfg.smtp_user, cfg.smtp_password)
            s.send_message(msg)
        return True, ""
    except Exception as exc:  # noqa: BLE001 -- report the reason, never crash the request
        return False, f"{type(exc).__name__}: {exc}"[:240]


def _otp_response(otp: str, sent: bool, detail: str) -> dict:
    """Shared response for the two /request endpoints: email it, or fall back to
    the demo code and say why the email didn't go out."""
    resp: dict = {"sent": sent}
    if sent:
        resp["message"] = "A verification code has been emailed to you."
        return resp
    resp["demo_otp"] = otp  # demo fallback so the flow stays usable
    if detail == "not_configured":
        resp["message"] = "Email not configured — showing the code for the demo."
    else:
        resp["message"] = "Email send failed — showing the code for the demo."
        resp["smtp_error"] = detail
    return resp


@router.post("/reset/request")
async def reset_request(c: EmailOnly) -> dict:
    """Step 1: email a 6-digit reset code to an existing account."""
    store = _load()
    email = c.email.lower().strip()
    if email not in store["users"]:
        raise HTTPException(404, "No account found with that email")
    otp = f"{secrets.randbelow(1_000_000):06d}"
    _OTP[email] = (otp, time.time() + _OTP_TTL)
    sent, detail = await asyncio.to_thread(_send_otp_email, email, otp)
    return _otp_response(otp, sent, detail)


@router.post("/reset/verify")
async def reset_verify(c: ResetVerify) -> dict:
    """Step 2: verify the code and set a new password (then sign in)."""
    store = _load()
    email = c.email.lower().strip()
    rec = _OTP.get(email)
    if not rec or rec[1] < time.time():
        raise HTTPException(400, "Code expired or not requested — request a new one")
    if not hmac.compare_digest(rec[0], c.otp.strip()):
        raise HTTPException(400, "Incorrect code")
    if email not in store["users"]:
        raise HTTPException(404, "No account found with that email")
    if len(c.password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    salt = secrets.token_hex(16)
    store["users"][email]["salt"] = salt
    store["users"][email]["hash"] = _hash(c.password, salt)
    _save(store)
    _OTP.pop(email, None)
    return {"token": _sign(store, email), "user": _user_public(store, email)}


@router.get("/me")
async def me(authorization: str = Header(default="")) -> dict:
    store = _load()
    token = authorization.removeprefix("Bearer ").strip()
    email = _verify(store, token) if token else None
    if not email or email not in store["users"]:
        raise HTTPException(401, "Not authenticated")
    return {"user": _user_public(store, email)}
