import os
import aiofiles
import secrets
import sqlite3
from pathlib import Path
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List

from helpers import get_current_user, setup_logger, limiter, AuthInfo, get_admin_access, get_db, safe_write

load_dotenv()
app = FastAPI(root_path="/v1/storage")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
logger = setup_logger("storage", f"../logs/storage/output.log")
UPLOAD_DIR = Path("files")
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = Path("storage.db")

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            original_name TEXT NOT NULL,
            disk_path TEXT NOT NULL UNIQUE,
            content_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_files_owner_id ON files(owner_id);")
        logger.info("Storage database initialized.")
init_db()

def sanitize_filename(filename: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)

class FileMetadata(BaseModel):
    id: str
    owner_id: str
    original_name: str
    content_type: str

@app.get("/health")
def health():
    return {"status": "storage is healthy"}

@app.post("/upload", response_model=FileMetadata)
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    user_upload_dir = UPLOAD_DIR / current_user.user_id
    user_upload_dir.mkdir(exist_ok=True)
    
    secure_disk_name = f"{secrets.token_hex(8)}_{sanitize_filename(file.filename)}"
    file_path_on_disk = user_upload_dir / secure_disk_name
    
    try:
        async with aiofiles.open(file_path_on_disk, "wb") as f:
            while content := await file.read(1024 * 1024):
                await f.write(content)
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail="Could not save file.")

    file_id = secrets.token_urlsafe(16)
    safe_write(db,
        "INSERT INTO files (id, owner_id, original_name, disk_path, content_type) VALUES (?, ?, ?, ?, ?)",
        (
            file_id,
            current_user.user_id,
            file.filename,
            str(file_path_on_disk),
            file.content_type,
        )
    )
    db.commit()
    
    logger.info(f"User '{current_user.user_id}' uploaded '{file.filename}' as file ID {file_id}")
    return {
        "id": file_id,
        "owner_id": current_user.user_id,
        "original_name": file.filename,
        "content_type": file.content_type,
    }

@app.get("/download/{file_id}")
@limiter.limit("60/minute")
async def download_file(request: Request, file_id: str, db: sqlite3.Connection = Depends(get_db)):
    result = db.execute(
        "SELECT disk_path FROM files WHERE id = ?", (file_id,)
    ).fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="File not found in DB")
    
    file_path = Path(result[0])
    if not file_path.is_file():
        logger.error(f"File ID {file_id} found in DB but missing on disk at {file_path}")
        raise HTTPException(status_code=404, detail="File not found on disk")
        
    return FileResponse(file_path)

@app.get("/list", response_model=List[FileMetadata])
@limiter.limit("30/minute")
async def list_user_files(request: Request, current_user: AuthInfo = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """
        SELECT id, owner_id, original_name, content_type
        FROM files
        WHERE owner_id = ?
        ORDER BY created_at DESC
        """,
        (current_user.user_id,)
    ).fetchall()
    return [dict(row) for row in rows]

@app.delete("/delete/{file_id}", status_code=200)
@limiter.limit("10/minute")
async def delete_file(
    request: Request,
    file_id: str,
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    
    db.row_factory = sqlite3.Row
    file_record = db.execute(
        "SELECT * FROM files WHERE id = ?", (file_id,)
    ).fetchone()

    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    if file_record["owner_id"] != current_user.user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this file")

    # remove from disk
    file_path = Path(file_record["disk_path"])
    if file_path.exists():
        file_path.unlink()
        logger.info(f"File physically removed: {file_path}")
    else:
        logger.warning(f"File metadata found but missing on disk: {file_path}")

    # remove from DB
    safe_write(db, "DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    logger.info(f"User '{current_user.user_id}' deleted file ID {file_id}")

    return {
        "message": f"{file_record['original_name']} deleted successfully"
    }

@app.get("/listall", response_model=List[FileMetadata])
@limiter.limit("10/minute")
async def list_all_files(request: Request, _=Depends(get_admin_access), db: sqlite3.Connection = Depends(get_db)):
    db.row_factory = sqlite3.Row
    rows = db.execute("""
        SELECT id, owner_id, original_name, content_type
        FROM files
        ORDER BY created_at DESC
    """).fetchall()
    return [dict(row) for row in rows]

