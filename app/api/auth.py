"""
Real (if minimal) authentication for the frontend.

Passwords are PBKDF2-HMAC-SHA256 hashed with a per-user salt; sessions are
HMAC-SHA256 signed tokens with an expiry. Stdlib only -- no new dependencies.
Users persist to .auth_store.json (gitignored). A demo admin is seeded on first
run. This is a genuine mechanism, but single-store and demo-seeded; swap the
store for a real DB before production.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

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


@router.post("/register", status_code=201)
async def register(c: Creds) -> dict:
    store = _load()
    email = c.email.lower().strip()
    if "@" not in email or len(c.password) < 6:
        raise HTTPException(400, "Valid email and a 6+ char password required")
    if email in store["users"]:
        raise HTTPException(409, "An account with that email already exists")
    salt = secrets.token_hex(16)
    store["users"][email] = {
        "name": c.name or email.split("@")[0].title(), "role": "Analyst",
        "salt": salt, "hash": _hash(c.password, salt),
    }
    _save(store)
    return {"token": _sign(store, email), "user": _user_public(store, email)}


@router.post("/reset")
async def reset(c: Creds) -> dict:
    """
    Demo-mode password reset: set a new password for an existing account and sign
    it in. NOTE: production must gate this behind an emailed one-time token — here
    there is no mail service, so this is intentionally a demo convenience.
    """
    store = _load()
    email = c.email.lower().strip()
    if email not in store["users"]:
        raise HTTPException(404, "No account found with that email")
    if len(c.password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    salt = secrets.token_hex(16)
    store["users"][email]["salt"] = salt
    store["users"][email]["hash"] = _hash(c.password, salt)
    _save(store)
    return {"token": _sign(store, email), "user": _user_public(store, email)}


@router.get("/me")
async def me(authorization: str = Header(default="")) -> dict:
    store = _load()
    token = authorization.removeprefix("Bearer ").strip()
    email = _verify(store, token) if token else None
    if not email or email not in store["users"]:
        raise HTTPException(401, "Not authenticated")
    return {"user": _user_public(store, email)}
