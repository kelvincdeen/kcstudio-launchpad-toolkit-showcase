import os
import logging
import sqlite3
import time
import random
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

import jwt
from fastapi import Depends, HTTPException, Request, Header, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address

JWT_SECRET = os.getenv("JWT_SECRET", "default-secret-key")
ALGORITHM = "HS256"
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
DB_PATH = os.getenv("DB_PATH", "data.db")

admin_key_scheme = APIKeyHeader(
    name="X-Admin-API-Key",
    scheme_name="AdminKey",
    description="Admin access key required for interal or server-to-server requests.",
    auto_error=False  # disable auto error so you can return your own message
)

reusable_oauth2 = HTTPBearer()
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# --- JWT ---
def create_jwt(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=24))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def decode_jwt(token: str) -> Optional[Dict[str, any]]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None

# --- Auth Classes ---
class AuthInfo:
    def __init__(self, user_id: str, email: str):
        self.user_id = user_id
        self.email = email

async def get_current_user(token: HTTPAuthorizationCredentials = Depends(reusable_oauth2)) -> AuthInfo:
    payload = decode_jwt(token.credentials)
    if payload is None:
        raise HTTPException(status_code=403, detail="Invalid or expired token")
    user_id = payload.get("sub")
    email = payload.get("email")
    if user_id is None or email is None:
        raise HTTPException(status_code=403, detail="Invalid token payload")
    return AuthInfo(user_id=user_id, email=email)

async def get_admin_access(x_admin_api_key: str = Security(admin_key_scheme)):
    if not x_admin_api_key or x_admin_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Admin API Key")
    return True

# --- Logging ---
def setup_logger(name: str, log_path: str):
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        return logger
    logger.setLevel(logging.INFO)
    log_path_obj = logging.FileHandler(log_path)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_path_obj.setFormatter(formatter)
    logger.addHandler(log_path_obj)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger

# --- SQLite WAL Mode and Retry ---
def get_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL;")
    try:
        yield db
    finally:
        db.close()

def safe_write(db, query: str, params=(), retries=3):
    for attempt in range(retries):
        try:
            return db.execute(query, params)
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < retries - 1:
                time.sleep(random.uniform(0.2, 0.5))
            else:
                raise

# --- Real Client IP, works with and without Cloudflare ---
def get_client_ip(request: Request) -> str:
    return request.headers.get("cf-connecting-ip") or request.headers.get("x-real-ip") or request.client.host

