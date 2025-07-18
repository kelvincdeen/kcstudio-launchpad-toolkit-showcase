import os
import sqlite3
import uuid
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

import resend
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from helpers import create_jwt, setup_logger, limiter, get_current_user, AuthInfo, get_db, safe_write

load_dotenv()
app = FastAPI(root_path="/v1/auth")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
logger = setup_logger("auth", f"../logs/auth/output.log")
resend.api_key = os.getenv("RESEND_API_KEY")
FRONTEND_DOMAIN = os.getenv("FRONTEND_DOMAIN")
DB_PATH = Path("users.db")

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            profile_photo TEXT,
            bio TEXT,
            social TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS login_tokens (
            token TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            expires_at DATETIME NOT NULL
        );
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_login_tokens_email ON login_tokens(email);")
        logger.info("Auth database initialized with users and login_tokens tables.")
init_db()

# --- MODELS ---

class LoginRequest(BaseModel):
    email: EmailStr

class VerifyRequest(BaseModel):
    token: str

class UserProfile(BaseModel):
    id: str
    email: EmailStr
    display_name: Optional[str] = None
    profile_photo: Optional[str] = None
    bio: Optional[str] = None
    social: Optional[dict] = None

class ProfileUpdate(BaseModel):
    display_name: Optional[str] = Field(None, min_length=3, max_length=50)
    profile_photo: Optional[str] = None
    bio: Optional[str] = None
    social: Optional[dict] = None

# --- SEND EMAIL ---

def send_login_email(email: str, token: str):
    if not resend.api_key:
        logger.error("Resend API key is not configured. Cannot send email.")
        return
    try:
        # use this if you want to use your own frontend domain-> verify_url = f"https://{FRONTEND_DOMAIN}/verify-login?token={token}"
        verify_url = f"https://launchpad.kcstudio.nl/verify-login?token={token}"

        # load from external template
        template_path = Path(__file__).parent / "email_template.html"
        with open(template_path, "r") as f:
            html = f.read()

        # replace placeholders
        html = html.format(
            verify_url=verify_url,
            frontend=os.getenv("FRONTEND_DOMAIN", "PROJECT_NAME")
        )

        params = {
            "from": f"Login <{os.getenv('RESEND_FROM_EMAIL')}>",
            "to": [email],
            "subject": "Your Magic Link to Log In",
            "html": html,
        }
        resend.Emails.send(params)
        logger.info(f"Magic link sent to {email}.")
    except Exception as e:
        logger.error(f"Failed to send email to {email}: {e}")

# --- ROUTES ---

@app.get("/health")
def health():
    return {"status": "auth is healthy"}

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, background_tasks: BackgroundTasks, db: sqlite3.Connection = Depends(get_db)):
    token, expires = str(uuid.uuid4()), datetime.now(timezone.utc) + timedelta(minutes=15)
    safe_write(db, "INSERT INTO login_tokens (token, email, expires_at) VALUES (?, ?, ?)",
                   (token, body.email.lower(), expires.isoformat()))
    db.commit()
    
    background_tasks.add_task(send_login_email, body.email.lower(), token)
    return {"message": "Magic link sent to your email."}

@app.post("/verify")
@limiter.limit("10/minute")

async def verify(request: Request, body: VerifyRequest, db: sqlite3.Connection = Depends(get_db)):
    db.row_factory = sqlite3.Row
    result = db.execute("SELECT email, expires_at FROM login_tokens WHERE token = ?", (body.token,)).fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Token not found or already used.")
    email = result['email']
    if datetime.now(timezone.utc) > datetime.fromisoformat(result['expires_at']):
        safe_write(db, "DELETE FROM login_tokens WHERE token = ?", (body.token,))
        db.commit()
        raise HTTPException(status_code=400, detail="Token has expired.")
    safe_write(db, "DELETE FROM login_tokens WHERE token = ?", (body.token,))

    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        new_user_id = str(uuid.uuid4())
        safe_write(db,
            "INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)",
            (new_user_id, email, email.split('@')[0])
        )
        user_id = new_user_id
        logger.info(f"New user created: {email} with ID {user_id}")
    else:
        user_id = user['id']
    db.commit()

    jwt_payload = {"sub": user_id, "email": email}
    session_jwt = create_jwt(jwt_payload)
    return {"access_token": session_jwt, "token_type": "bearer"}

@app.get("/me", response_model=UserProfile)
async def get_me(request: Request, current_user: AuthInfo = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    db.row_factory = sqlite3.Row
    user = db.execute("SELECT * FROM users WHERE id = ?", (current_user.user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user_dict = dict(user)
    if user_dict.get("social"):
        user_dict["social"] = json.loads(user_dict["social"])
    return user_dict

@app.put("/me", response_model=UserProfile)
async def update_me(
    request: Request,
    update_data: ProfileUpdate,
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    update_fields = update_data.dict(exclude_unset=True)
    if not update_fields:
        raise HTTPException(status_code=400, detail="No update data provided.")
    
    set_clauses = []
    params = []
    
    for key, value in update_fields.items():
        set_clauses.append(f"{key} = ?")
        # Serialize dict to JSON string for the 'social' field
        if key == "social" and isinstance(value, dict):
            params.append(json.dumps(value))
        else:
            params.append(value)

    params.append(current_user.user_id)
    
    sql_query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"

    db.row_factory = sqlite3.Row
    safe_write(db, sql_query, tuple(params))
    db.commit()

    user = db.execute("SELECT * FROM users WHERE id = ?", (current_user.user_id,)).fetchone()
    if not user:
        logger.warning(f"User with ID {current_user.user_id} was not found after update. Possible race condition or data inconsistency.")
        raise HTTPException(status_code=404, detail="User not found after update.")
            
    user_dict = dict(user)
    if user_dict.get("social"):
        user_dict["social"] = json.loads(user_dict["social"])
    logger.info(f"User profile updated for {current_user.email} with fields: {list(update_fields.keys())}")
    return user_dict

@app.get("/public-profile/{user_id}")
@limiter.limit("30/minute")
async def public_profile(request: Request, user_id: str, db: sqlite3.Connection = Depends(get_db)):
    db.row_factory = sqlite3.Row
    user = db.execute(
        "SELECT display_name, profile_photo, bio, social FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_dict = dict(user)
    if user_dict.get("social"):
        user_dict["social"] = json.loads(user_dict["social"])
    return {
        "display_name": user_dict["display_name"],
        "profile_photo": user_dict["profile_photo"],
        "bio": user_dict["bio"],
        "social": user_dict["social"]
    }

@app.delete("/delete-me", status_code=200)
@limiter.limit("5/minute")
async def delete_me(request: Request, current_user: AuthInfo = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    safe_write(db, "DELETE FROM users WHERE id = ?", (current_user.user_id,))
    safe_write(db, "DELETE FROM login_tokens WHERE email = ?", (current_user.email,))
    db.commit()
    logger.info(f"User {current_user.email} deleted their profile.")
    return { "message": "Your profile has been deleted." }
    

