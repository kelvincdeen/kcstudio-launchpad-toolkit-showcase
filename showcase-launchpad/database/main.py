import os
import sqlite3
import json
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from helpers import get_current_user, get_admin_access, setup_logger, limiter, AuthInfo, get_db, safe_write

load_dotenv()
app = FastAPI(root_path="/v1/database")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
logger = setup_logger("database", f"../logs/database/output.log")
DB_PATH = Path("data.db")

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            title TEXT,
            type TEXT,
            category TEXT,
            tags TEXT,
            status TEXT DEFAULT 'draft',
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        logger.info("Database initialized with flexible JSON hybrid schema.")
        db.execute("CREATE INDEX IF NOT EXISTS idx_items_owner_id ON items(owner_id);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_items_type ON items(type);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_items_category ON items(category);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_items_created_at ON items(created_at);")
        logger.info("Database indexes created.")
init_db()

# --- Models ---

class Item(BaseModel):
    id: Optional[int]
    owner_id: str
    slug: str
    title: Optional[str]
    type: Optional[str]
    category: Optional[str]
    tags: Optional[List[str]] = []
    status: Optional[str] = "draft"
    data: Optional[dict] = {}
    created_at: Optional[str]
    updated_at: Optional[str]

class ItemCreate(BaseModel):
    slug: str = Field(..., min_length=3)
    title: Optional[str]
    type: Optional[str]
    category: Optional[str]
    tags: Optional[List[str]] = []
    status: Optional[str] = "draft"
    data: Optional[dict] = {}

class ItemUpdate(BaseModel):
    title: Optional[str]
    type: Optional[str]
    category: Optional[str]
    tags: Optional[List[str]] = []
    status: Optional[str] = "draft"
    data: Optional[dict] = {}

# --- Endpoints ---

@app.get("/health")
def health():
    return {"status": "database is healthy"}

@app.get("/listall", response_model=List[Item])
@limiter.limit("30/minute")
def list_entries(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    _ = Depends(get_admin_access),
    status: Optional[str] = None,
    type: Optional[str] = None,
    category: Optional[str] = None,
    owner: Optional[str] = None,
    created_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    created_to: Optional[str] = Query(None, description="YYYY-MM-DD"),
):
    sql = "SELECT * FROM items WHERE 1=1"
    params = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if type:
        sql += " AND type = ?"
        params.append(type)
    if category:
        sql += " AND category = ?"
        params.append(category)
    if owner:
        sql += " AND owner_id = ?"
        params.append(owner)
    if created_from:
        sql += " AND created_at >= ?"
        params.append(created_from)
    if created_to:
        sql += " AND created_at <= ?"
        params.append(created_to)
    sql += " ORDER BY created_at DESC"

    rows = db.execute(sql, params).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["tags"] = json.loads(item["tags"]) if item["tags"] else []
        item["data"] = json.loads(item["data"]) if item["data"] else {}
        result.append(item)
    return result

@app.get("/listuser", response_model=List[Item])
@limiter.limit("30/minute")
def list_user_entries(
    request: Request,
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    rows = db.execute(
        "SELECT * FROM items WHERE owner_id = ? ORDER BY created_at DESC",
        (current_user.user_id,)
    ).fetchall()

    result = []
    for row in rows:
        item = dict(row)
        item["tags"] = json.loads(item["tags"]) if item["tags"] else []
        item["data"] = json.loads(item["data"]) if item["data"] else {}
        result.append(item)

    return result

@app.get("/listpublic", response_model=List[dict])
@limiter.limit("30/minute")
def list_public_entries(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    type: Optional[str] = None,
    category: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    sql = "SELECT * FROM items WHERE status = 'published'"
    params = []

    if type:
        sql += " AND type = ?"
        params.append(type)

    if category:
        sql += " AND category = ?"
        params.append(category)

    if keyword:
        sql += " AND (title LIKE ? OR slug LIKE ?)"
        params.extend([f"%{keyword}%", f"%{keyword}%"])

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = db.execute(sql, params).fetchall()
    result = []
    for row in rows:
        row = dict(row)
        result.append({
            "slug": row["slug"],
            "title": row["title"],
            "type": row["type"],
            "category": row["category"],
            "status": row["status"],
            "tags": json.loads(row["tags"]) if row["tags"] else [],
            "data": json.loads(row["data"]) if row["data"] else {},
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return result


@app.get("/retrieve/{slug}", response_model=dict)
@limiter.limit("30/minute")
def retrieve_entry(request: Request, slug: str, db: sqlite3.Connection = Depends(get_db)):
    row = db.execute(
        "SELECT * FROM items WHERE slug = ? AND status = 'published'", (slug,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Item not found")

    row = dict(row)
    return {
        "slug": row["slug"],
        "title": row["title"],
        "type": row["type"],
        "category": row["category"],
        "tags": json.loads(row["tags"]) if row["tags"] else [],
        "data": json.loads(row["data"]) if row["data"] else {},
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


@app.post("/create", response_model=Item, status_code=201)
@limiter.limit("15/minute")
def create_entry(
    request: Request,
    item: ItemCreate,
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    logger.info(f"User '{current_user.user_id}' creating entry '{item.slug}'")
    try:
        cursor = safe_write(db, """
            INSERT INTO items (owner_id, slug, title, type, category, tags, status, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user.user_id,
            item.slug,
            item.title,
            item.type,
            item.category,
            json.dumps(item.tags),
            item.status,
            json.dumps(item.data),
        ))
        db.commit()
    except sqlite3.IntegrityError:
         raise HTTPException(status_code=409, detail=f"Item with slug '{item.slug}' already exists.")

    new_item = db.execute("SELECT * FROM items WHERE id = ?", (cursor.lastrowid,)).fetchone()
    item_dict = dict(new_item)
    item_dict["tags"] = json.loads(item_dict["tags"]) if item_dict["tags"] else []
    item_dict["data"] = json.loads(item_dict["data"]) if item_dict["data"] else {}
    return item_dict

@app.put("/update/{slug}", response_model=Item)
@limiter.limit("15/minute")
def update_entry(
    request: Request,
    slug: str,
    item_update: ItemUpdate,
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    existing_item = db.execute("SELECT owner_id FROM items WHERE slug = ?", (slug,)).fetchone()
    if not existing_item:
        raise HTTPException(status_code=404, detail="Item not found")
    if existing_item["owner_id"] != current_user.user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this item")

    safe_write(db, """
        UPDATE items
        SET title = ?, type = ?, category = ?, tags = ?, status = ?, data = ?, updated_at = CURRENT_TIMESTAMP
        WHERE slug = ?
    """, (
        item_update.title,
        item_update.type,
        item_update.category,
        json.dumps(item_update.tags),
        item_update.status,
        json.dumps(item_update.data),
        slug
    ))
    db.commit()
    updated_item = db.execute("SELECT * FROM items WHERE slug = ?", (slug,)).fetchone()
    item_dict = dict(updated_item)
    item_dict["tags"] = json.loads(item_dict["tags"]) if item_dict["tags"] else []
    item_dict["data"] = json.loads(item_dict["data"]) if item_dict["data"] else {}
    return item_dict

@app.delete("/delete/{slug}", status_code=200)
@limiter.limit("15/minute")
def delete_entry(
    request: Request,
    slug: str,
    current_user: AuthInfo = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    existing_item = db.execute("SELECT owner_id FROM items WHERE slug = ?", (slug,)).fetchone()
    if not existing_item:
        raise HTTPException(status_code=404, detail="Item not found")
    if existing_item["owner_id"] != current_user.user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this item")

    safe_write(db, "DELETE FROM items WHERE slug = ?", (slug,))
    db.commit()
    logger.info(f"User '{current_user.user_id}' deleted item with slug '{slug}'")
    return {"message": f"Item '{slug}' deleted successfully"}

@app.get("/search", response_model=List[dict])
@limiter.limit("30/minute")
def search_entries(
    request: Request,
    db: sqlite3.Connection = Depends(get_db),
    keyword: str = Query(..., description="Search keyword"),
):
    sql = "SELECT * FROM items WHERE status = 'published' AND (title LIKE ? OR slug LIKE ?) ORDER BY created_at DESC"
    param = f"%{keyword}%"
    rows = db.execute(sql, (param, param)).fetchall()

    result = []
    for row in rows:
        row = dict(row)
        result.append({
            "slug": row["slug"],
            "title": row["title"],
            "type": row["type"],
            "category": row["category"],
            "tags": json.loads(row["tags"]) if row["tags"] else [],
            "data": json.loads(row["data"]) if row["data"] else {},
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return result

