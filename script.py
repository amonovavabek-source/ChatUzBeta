
import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="ChatUz API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "chatuz.db"
ADMIN_KEY = os.environ.get("CHATUZ_ADMIN_KEY", "")
sessions = {}


def now():
    return datetime.now(timezone.utc).isoformat()


def connect_db():
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        );

        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT,
            group_id INTEGER,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)


init_db()


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200_000
    ).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    salt, expected = stored.split("$", 1)
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200_000
    ).hex()
    return hmac.compare_digest(actual, expected)


class Credentials(BaseModel):
    username: str
    password: str


class NewGroup(BaseModel):
    name: str


class NewMessage(BaseModel):
    body: str
    recipient: str | None = None
    group_id: int | None = None


def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Avval akkauntingizga kiring")

    token = authorization[7:]
    username = sessions.get(token)
    if not username:
        raise HTTPException(401, "Sessiya tugagan. Qayta kiring")

    return username


@app.get("/")
def home():
    return {"app": "ChatUz", "status": "online"}


@app.post("/register")
def register(data: Credentials):
    username = data.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
        raise HTTPException(
            400, "Username 3-20 belgi: harf, raqam yoki _"
        )

    if not re.fullmatch(r"[A-Za-z0-9]{5,15}", data.password):
        raise HTTPException(
            400, "Parol 5-15 ta harf yoki raqam bo'lishi kerak"
        )

    try:
        with connect_db() as db:
            db.execute(
                """INSERT INTO users
                   (username, password_hash, created_at)
                   VALUES (?, ?, ?)""",
                (username, hash_password(data.password), now())
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Bu username band")

    return {"message": "Akkaunt yaratildi"}


@app.post("/login")
def login(data: Credentials):
    with connect_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (data.username.strip(),)
        ).fetchone()

        if not user or not verify_password(
            data.password, user["password_hash"]
        ):
            raise HTTPException(401, "Username yoki parol xato")

        db.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (now(), user["id"])
        )

    token = secrets.token_urlsafe(32)
    sessions[token] = user["username"]

    return {"token": token, "username": user["username"]}


@app.get("/users")
def users(me: str = Depends(current_user)):
    with connect_db() as db:
        rows = db.execute(
            "SELECT username FROM users WHERE username != ? "
            "ORDER BY username", (me,)
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/groups")
def groups(me: str = Depends(current_user)):
    with connect_db() as db:
        rows = db.execute(
            "SELECT id, name, created_by FROM groups ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/groups")
def create_group(
    data: NewGroup,
    me: str = Depends(current_user)
):
    name = data.name.strip()
    if not name or len(name) > 40:
        raise HTTPException(400, "Guruh nomi 1-40 belgi bo'lsin")

    with connect_db() as db:
        cur = db.execute(
            "INSERT INTO groups (name, created_by, created_at) "
            "VALUES (?, ?, ?)",
            (name, me, now())
        )
        group_id = cur.lastrowid

    return {"id": group_id, "name": name}


@app.get("/messages")
def get_messages(
    with_user: str | None = None,
    group_id: int | None = None,
    me: str = Depends(current_user)
):
    if (with_user is None) == (group_id is None):
        raise HTTPException(
            400, "Bitta chat: with_user yoki group_id tanlang"
        )

    with connect_db() as db:
        if with_user is not None:
            rows = db.execute(
                """SELECT id, sender, recipient, body, created_at
                   FROM messages
                   WHERE group_id IS NULL
                   AND ((sender = ? AND recipient = ?)
                     OR (sender = ? AND recipient = ?))
                   ORDER BY id DESC LIMIT 200""",
                (me, with_user, with_user, me)
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT id, sender, group_id, body, created_at
                   FROM messages WHERE group_id = ?
                   ORDER BY id DESC LIMIT 200""",
                (group_id,)
            ).fetchall()

    return [dict(row) for row in reversed(rows)]


@app.post("/messages")
def send_message(
    data: NewMessage,
    me: str = Depends(current_user)
):
    body = data.body.strip()

    if not body or len(body) > 2000:
        raise HTTPException(400, "Xabar 1-2000 belgi bo'lsin")

    if (data.recipient is None) == (data.group_id is None):
        raise HTTPException(400, "Qabul qiluvchi yoki guruhni tanlang")

    with connect_db() as db:
        if data.recipient is not None:
            recipient = db.execute(
                "SELECT username FROM users WHERE username = ?",
                (data.recipient,)
            ).fetchone()
            if not recipient or recipient["username"] == me:
                raise HTTPException(404, "Foydalanuvchi topilmadi")
        else:
            group = db.execute(
                "SELECT id FROM groups WHERE id = ?",
                (data.group_id,)
            ).fetchone()
            if not group:
                raise HTTPException(404, "Guruh topilmadi")

        cur = db.execute(
            """INSERT INTO messages
               (sender, recipient, group_id, body, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (me, data.recipient, data.group_id, body, now())
        )

    return {"id": cur.lastrowid, "status": "sent"}


@app.get("/admin/users")
def admin_users(x_admin_key: str | None = Header(default=None)):
    if not ADMIN_KEY or not x_admin_key or not hmac.compare_digest(
        x_admin_key, ADMIN_KEY
    ):
        raise HTTPException(403, "Admin ruxsati yo'q")

    with connect_db() as db:
        rows = db.execute(
            """SELECT username, created_at, last_login
               FROM users ORDER BY created_at DESC"""
        ).fetchall()

    return [dict(row) for row in rows]


@app.post("/logout")
def logout(
    authorization: str | None = Header(default=None),
    me: str = Depends(current_user)
):
    token = authorization[7:]
    sessions.pop(token, None)
    return {"status": "logged out"}


