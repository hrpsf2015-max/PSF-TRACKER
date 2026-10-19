import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

log = logging.getLogger("psf")

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    log.warning("SECRET_KEY not set - using a random one; everyone is logged out on each restart.")
TOKEN_HOURS = int(os.getenv("TOKEN_HOURS", "12"))
ITERATIONS = 240_000

bearer = HTTPBearer(auto_error=False)


def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), ITERATIONS).hex()
    return f"pbkdf2${ITERATIONS}${salt}${h}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, it, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(it)).hex()
        return hmac.compare_digest(calc, h)
    except Exception:
        return False


def make_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": str(user.id), "exp": exp}, SECRET_KEY, algorithm="HS256")


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)
) -> User:
    if not creds:
        raise HTTPException(401, "Not logged in")
    try:
        data = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        user = db.get(User, int(data["sub"]))
    except Exception:
        raise HTTPException(401, "Session expired, please log in again")
    if not user or not user.active:
        raise HTTPException(401, "Account disabled or not found")
    return user


def admin_only(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


# --- simple brute-force protection (in memory; fine for a single small server) ---
_fails: dict[str, list[float]] = {}
MAX_FAILS, WINDOW = 5, 600


def _key(request: Request, username: str) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")
    return f"{username.lower()}|{ip}"


def check_lockout(request: Request, username: str):
    k = _key(request, username)
    now = time.time()
    recent = [t for t in _fails.get(k, []) if now - t < WINDOW]
    _fails[k] = recent
    if len(recent) >= MAX_FAILS:
        raise HTTPException(429, "Too many failed attempts. Try again in 10 minutes.")


def record_failure(request: Request, username: str):
    _fails.setdefault(_key(request, username), []).append(time.time())


def clear_failures(request: Request, username: str):
    _fails.pop(_key(request, username), None)
