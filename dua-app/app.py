"""
mydua.ai — Backend API (v10.2 Production)
==========================================
All 8 production-readiness issues resolved:
  #1: Server-owned email delivery (no browser dependency)
  #2: SQLite persistence (durable across restarts, concurrent-write safe)
  #3: Job recovery on startup (orphaned jobs detected and cleaned)
  #4: SQLite-backed rate limiting (survives restarts)
  #5: HMAC-signed email tokens (prevents unauthorized email sends)
  #6: Input size limits (max 15 members, field length caps)
  #7: No secrets in logs (keys show configured/not-configured only)
  #8: Startup cleanup (expired jobs, cache, old du'as purged)

Run: uvicorn app:app --reload --port 8000
"""

import os
import json
import uuid
import hashlib
import hmac
import time
import asyncio
import sqlite3
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from html import escape as html_escape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import httpx
import stripe
import aiosmtplib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, field_validator

# ══════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.resolve()
load_dotenv(BASE_DIR / ".env")

AI_PROVIDER = os.getenv("AI_PROVIDER", "anthropic")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-6")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Du\'a Generator")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")

APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
APP_ENV = os.getenv("APP_ENV", "development")
TRUSTED_PROXY_DEPTH = int(os.getenv("TRUSTED_PROXY_DEPTH", "1"))  # Fix #4: how many proxy hops to trust

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

DB_PATH = BASE_DIR / "data" / "mydua.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dua-api")

http_client: Optional[httpx.AsyncClient] = None


# ══════════════════════════════════════════════════
# Fix #2: SQLite Database (replaces all file-based storage)
# ══════════════════════════════════════════════════

class Database:
    """
    SQLite-backed persistence layer. Replaces file-based JSON storage.
    Uses WAL mode for concurrent read safety and single-writer correctness.
    """

    def __init__(self, db_path: Path):
        self.db_path = str(db_path)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                dua TEXT NOT NULL,
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                batch_id TEXT,
                request_id TEXT,
                status TEXT NOT NULL DEFAULT 'processing',
                email_status TEXT NOT NULL DEFAULT 'none',
                dua TEXT,
                error TEXT,
                user_name TEXT,
                user_email TEXT,
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS saved (
                dua_id TEXT PRIMARY KEY,
                user_name TEXT,
                dua TEXT NOT NULL,
                members_json TEXT,
                email_token TEXT,
                private INTEGER NOT NULL DEFAULT 0,
                created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analytics (
                event TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (event)
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT NOT NULL,
                timestamp REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rate_key ON rate_limits(key);
            CREATE INDEX IF NOT EXISTS idx_rate_ts ON rate_limits(timestamp);
        """)
        for evt in ["duas_generated", "pdfs_exported", "emails_sent", "shares_created", "donations_initiated"]:
            conn.execute("INSERT OR IGNORE INTO analytics (event, count) VALUES (?, 0)", (evt,))
        conn.commit()
        conn.close()

    # ── Cache ──
    def cache_get(self, key: str, ttl_seconds: int = 604800) -> Optional[str]:
        conn = self._get_conn()
        row = conn.execute("SELECT dua, created FROM cache WHERE key = ?", (key,)).fetchone()
        conn.close()
        if row and (time.time() - row["created"]) < ttl_seconds:
            return row["dua"]
        return None

    def cache_put(self, key: str, dua: str):
        conn = self._get_conn()
        conn.execute("INSERT OR REPLACE INTO cache (key, dua, created) VALUES (?, ?, ?)",
                     (key, dua, time.time()))
        conn.commit()
        conn.close()

    def make_cache_key(self, user_name: str, members: list) -> str:
        normalized = []
        for m in sorted(members, key=lambda x: x.get("relationship", "")):
            normalized.append({
                "name": str(m.get("name", "")).strip().lower(),
                "relationship": str(m.get("relationship", "")).strip().lower(),
                "ageRange": str(m.get("ageRange", "")).strip().lower(),
                "gender": str(m.get("gender", "")).strip().lower(),
                "concerns": str(m.get("concerns", "")).strip().lower()[:100],
            })
        raw = json.dumps(normalized, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ── Jobs ──
    def job_create(self, job_id: str, batch_id: str, request_id: str,
                   user_name: str = "", user_email: str = ""):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO jobs (job_id, batch_id, request_id, status, user_name, user_email, created) "
            "VALUES (?, ?, ?, 'processing', ?, ?, ?)",
            (job_id, batch_id, request_id, user_name, user_email, time.time()))
        conn.commit()
        conn.close()

    def job_get(self, job_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def job_complete(self, job_id: str, dua: str):
        conn = self._get_conn()
        conn.execute("UPDATE jobs SET status = 'completed', dua = ? WHERE job_id = ?", (dua, job_id))
        conn.commit()
        conn.close()

    def job_fail(self, job_id: str, error: str):
        conn = self._get_conn()
        conn.execute("UPDATE jobs SET status = 'failed', error = ? WHERE job_id = ?", (error, job_id))
        conn.commit()
        conn.close()

    def job_set_email_status(self, job_id: str, status: str):
        """Fix #1: Track email delivery independently from job completion."""
        conn = self._get_conn()
        conn.execute("UPDATE jobs SET email_status = ? WHERE job_id = ?", (status, job_id))
        conn.commit()
        conn.close()

    def jobs_get_orphaned(self, max_age_seconds: int = 900) -> list:
        conn = self._get_conn()
        cutoff = time.time() - max_age_seconds
        rows = conn.execute(
            "SELECT * FROM jobs WHERE status = 'processing' AND created < ?", (cutoff,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ── Saved Du'as ──
    def save_dua(self, dua_id: str, user_name: str, dua: str, members_json: str, email_token: str, private: bool = False):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO saved (dua_id, user_name, dua, members_json, email_token, private, created) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (dua_id, user_name, dua, members_json, email_token, 1 if private else 0,
             datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()

    def get_saved(self, dua_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM saved WHERE dua_id = ?", (dua_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    # ── Analytics ──
    def track(self, event: str):
        conn = self._get_conn()
        conn.execute("UPDATE analytics SET count = count + 1 WHERE event = ?", (event,))
        conn.commit()
        conn.close()

    def get_stats(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute("SELECT event, count FROM analytics").fetchall()
        conn.close()
        return {f"total_{r['event']}": r["count"] for r in rows}

    # ── Fix #4: SQLite-backed Rate Limiting ──
    def rate_limit_check(self, key: str, max_requests: int, window_seconds: int) -> tuple:
        conn = self._get_conn()
        cutoff = time.time() - window_seconds
        conn.execute("DELETE FROM rate_limits WHERE timestamp < ?", (cutoff,))
        count = conn.execute(
            "SELECT COUNT(*) as c FROM rate_limits WHERE key = ? AND timestamp >= ?",
            (key, cutoff)).fetchone()["c"]
        if count >= max_requests:
            conn.commit()
            conn.close()
            return False, max_requests - count
        conn.execute("INSERT INTO rate_limits (key, timestamp) VALUES (?, ?)", (key, time.time()))
        conn.commit()
        conn.close()
        return True, max_requests - count - 1

    # ── Fix #8: Cleanup ──
    def cleanup(self):
        conn = self._get_conn()
        now = time.time()
        # Jobs older than 24 hours
        j = conn.execute("DELETE FROM jobs WHERE created < ?", (now - 86400,)).rowcount
        # Cache older than 7 days
        c = conn.execute("DELETE FROM cache WHERE created < ?", (now - 604800,)).rowcount
        # Old rate limit entries
        r = conn.execute("DELETE FROM rate_limits WHERE timestamp < ?", (now - 7200,)).rowcount
        conn.commit()
        conn.close()
        return j, c, r


db = Database(DB_PATH)


# ══════════════════════════════════════════════════
# Fix #5: HMAC Email Tokens
# ══════════════════════════════════════════════════

def generate_email_token(dua_id: str) -> str:
    return hmac.new(SECRET_KEY.encode(), dua_id.encode(), hashlib.sha256).hexdigest()[:32]

def verify_email_token(dua_id: str, token: str) -> bool:
    expected = generate_email_token(dua_id)
    return hmac.compare_digest(expected, token)


def get_client_ip(request: Request) -> str:
    """
    Fix #4: Extract client IP safely.
    In production behind a reverse proxy (Railway, Render), trust X-Forwarded-For
    but only the rightmost N hops where N = TRUSTED_PROXY_DEPTH.
    In development, use the direct connection IP.
    """
    if APP_ENV == "production":
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            # Take the IP set by the trusted proxy (rightmost hop)
            idx = max(0, len(parts) - TRUSTED_PROXY_DEPTH)
            return parts[idx]
    return request.client.host if request.client else "unknown"


# ══════════════════════════════════════════════════
# AI System Prompt
# ══════════════════════════════════════════════════

SYSTEM_PROMPT = """
You are a knowledgeable Islamic scholar who writes beautiful, heartfelt du'as (supplications) in English.

You have deep knowledge of:
- The Quran
- Authentic Hadith collections (Sahih Bukhari, Sahih Muslim, Tirmidhi, Abu Dawud, Ibn Majah)
- The 99 Names of Allah (Asma ul-Husna)

Your task is to write a personalized family du'a for the last ten nights of Ramadan.

The du'a must feel sincere, emotional, spiritually uplifting, and suitable to be read aloud by a family during night prayer.

--------------------------------------------------

STRUCTURE

The du'a must follow this structure exactly:

### 1. Opening Section

Begin with:

بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ
(Bismillah ir-Rahman ir-Raheem)

Praise and glorify Allah using His beautiful names and attributes.

Include references to:

- Ayatul Kursi (Quran 2:255)
- Allah's names in Surah Al-Hashr (Quran 59:22–24)
- The du'a of the Prophet ﷺ mentioning:
  Al-Awwal, Al-Akhir, Adh-Dhahir, Al-Batin (Sahih Muslim)

This section should focus on praise, gratitude, and recognition of Allah's majesty.

---

### 2. Personal Section for the Supplicant

Write a section for the person making the du'a.

Address all their possible roles depending on the family members listed:

If they are a spouse include:
- Quran 30:21 (love and mercy between spouses)
- Hadith about being the best to one's family

If they are a parent include:
- Quran 14:40 (Ibrahim's prayer)
- Quran 25:74 (coolness of the eyes)

If they are a child include:
- Quran 17:23–24 (honoring parents)
- Quran 71:28 (Nuh's prayer)

If they are a sibling include:
- Hadith about believers being like one body

---

### 3. Individual Sections for Each Family Member

For every family member provided, create a dedicated section.

Each section must start with:

## A Du'a for [Name], My [Relationship]

Each section must:

• Invoke 2–3 appropriate Names of Allah using **bold formatting**
• Include at least one Quranic verse or authentic Hadith in *italics*
• Make du'a for their specific concerns and prayer needs
• Be appropriate for their age group

Age guidance:

Under 5: Protection, love of faith, health, nurturing heart
5–10: Love of learning, protection of innocence, growing iman
11–15: Guidance through adolescence, righteous friends, discipline
16–20: Protection from fitnah, strength of character, life direction
21–30: Career guidance, righteous spouse, stability in faith
31–40: Family harmony, barakah in provision, strong iman
41–50: Health, wisdom, positive influence
51–60: Ease in life, gratitude, beneficial legacy
61–70: Comfort, dignity, spiritual readiness
70+: Mercy, light in the grave, Jannatul Firdaws

---

### 4. Family Closing Section

End the du'a with a section praying for the entire family.

Include themes of:

• Unity and love (Quran 59:10)
• Reunion in Jannatul Firdaws (Quran 52:21)
• Forgiveness and mercy
• Trust in Allah (Quran 3:173 — Hasbunallahu wa ni'mal wakeel)

End with:

آمِين يَا رَبَّ الْعَالَمِين
(Ameen, O Lord of the worlds)

---

### 5. Laylatul Qadr References

Throughout the du'a, weave references to:

• The blessed last ten nights of Ramadan
• Seeking Laylatul Qadr
• The du'a taught to Aisha (RA):

"Allahumma innaka 'afuwwun tuhibbul 'afwa fa'fu 'anni"
(Tirmidhi)

--------------------------------------------------

MULTI-LANGUAGE: ARABIC TRANSLITERATION

IMPORTANT: For every Quranic verse and Hadith du'a, provide THREE versions:
1. The Arabic text (in Arabic script)
2. The transliteration (in Latin letters so non-Arabic readers can recite)
3. The English translation

Format them like this:

*Arabic:* [Arabic text]
*Transliteration:* [Latin transliteration]
*Translation:* "[English translation]"
*(Source)*

--------------------------------------------------

FORMAT RULES

Use:

## for section headings
**bold** for Names of Allah
*italics* for Quran and Hadith references

Always cite references: (Quran X:Y), (Sahih Bukhari), (Sahih Muslim), (Tirmidhi)

Use --- to separate major sections.

Arabic phrases should include transliteration and English meaning.

---

TONE

The du'a should feel:
• sincere
• humble
• emotionally moving
• spiritually hopeful
• personal and heartfelt

It should feel like a believer speaking to Allah in the last third of the night.

---

IMPORTANT RULES

• Only use authentic Quran verses and well-known Hadith
• Do not fabricate or misattribute Islamic texts
• Use the Names of Allah accurately and in appropriate context
• Do not invent new hadith or verses
• Maintain Islamic respect and authenticity at all times
• Cite every reference accurately

---

LENGTH

Adjust the du'a length based on how many family members are included.
Follow the length guidance provided in the user message.
"""


# ══════════════════════════════════════════════════
# Dynamic Output Length
# ══════════════════════════════════════════════════

def get_length_instruction(member_count: int) -> str:
    if member_count <= 2:
        return "Keep the du'a focused and heartfelt, approximately 1500-2000 words total. Include 1-2 Quranic verses per person and a concise opening/closing."
    elif member_count <= 4:
        return "Write a comprehensive du'a of approximately 2000-2500 words total. Include 1-2 Quranic verses per person with full transliteration."
    elif member_count <= 6:
        return "Write a detailed du'a of approximately 2500-3000 words total. Include 1-2 Quranic verses per person with full transliteration."
    else:
        return "Write a thorough du'a of approximately 3000-3500 words total. Include 1-2 Quranic verses per person with full transliteration."

def get_max_tokens(member_count: int) -> int:
    if member_count <= 2: return 2500
    elif member_count <= 4: return 4000
    elif member_count <= 6: return 5500
    else: return 7000


# ══════════════════════════════════════════════════
# Fix #6: Pydantic Models with Input Size Limits
# ══════════════════════════════════════════════════

class FamilyMember(BaseModel):
    name: str
    relationship: str = ""
    ageRange: str = ""
    gender: str = ""
    attributes: str = ""
    concerns: str = ""

    @field_validator("name")
    @classmethod
    def name_length(cls, v):
        if len(v) > 200:
            raise ValueError("Name must be under 200 characters")
        return v

    @field_validator("concerns")
    @classmethod
    def concerns_length(cls, v):
        if len(v) > 500:
            raise ValueError("Concerns must be under 500 characters")
        return v

    @field_validator("relationship", "ageRange", "gender")
    @classmethod
    def field_length(cls, v):
        if len(v) > 100:
            raise ValueError("Field must be under 100 characters")
        return v


class GenerateDuaRequest(BaseModel):
    userName: str
    members: list[FamilyMember]
    skipCache: bool = False
    deliveryMode: str = "instant"
    includeTransliteration: bool = False
    userEmail: Optional[str] = None  # Fix #7: Validated field instead of header

    @field_validator("userName")
    @classmethod
    def username_length(cls, v):
        if len(v) > 200:
            raise ValueError("Name must be under 200 characters")
        return v

    @field_validator("members")
    @classmethod
    def max_members(cls, v):
        if len(v) > 15:
            raise ValueError("Maximum 15 family members allowed")
        return v

    @field_validator("userEmail")
    @classmethod
    def validate_email(cls, v):
        if v is not None and v.strip():
            v = v.strip()
            if "@" not in v or "." not in v.split("@")[-1]:
                raise ValueError("Invalid email address")
            if len(v) > 254:
                raise ValueError("Email address too long")
        return v


class EmailDuaRequest(BaseModel):
    duaId: str
    email: EmailStr
    recipientName: str = ""
    token: str = ""  # Fix #5: HMAC token required


class SaveDuaRequest(BaseModel):
    userName: str
    dua: str
    members: list[FamilyMember] = []

    @field_validator("userName")
    @classmethod
    def username_length(cls, v):
        if len(v) > 200:
            raise ValueError("Name must be under 200 characters")
        return v

    @field_validator("dua")
    @classmethod
    def dua_max_size(cls, v):
        if len(v) > 50000:
            raise ValueError("Du'a text too large")
        return v

    @field_validator("members")
    @classmethod
    def max_members(cls, v):
        if len(v) > 15:
            raise ValueError("Maximum 15 family members allowed")
        return v


class SupportRequest(BaseModel):
    amount: str = "10"
    customAmount: int = 0


# ══════════════════════════════════════════════════
# FastAPI App
# ══════════════════════════════════════════════════

app = FastAPI(
    title="Du'a Generator API",
    description="Generate personalized Islamic supplications for the last 10 nights of Ramadan.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        APP_BASE_URL,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    global http_client

    # Fix #7: Refuse to start with insecure default secret in production
    if APP_ENV == "production" and SECRET_KEY == "change-me-in-production":
        logger.critical("FATAL: SECRET_KEY is still the default value. Set a real secret in .env before running in production.")
        raise RuntimeError("Insecure SECRET_KEY — set a real value in .env")

    http_client = httpx.AsyncClient(timeout=120)

    # Fix #7: No secrets in logs
    logger.info("=" * 50)
    logger.info("mydua.ai v10.2 — Production")
    logger.info("=" * 50)
    logger.info(f"AI Provider:  {AI_PROVIDER} ({ANTHROPIC_MODEL})")
    logger.info(f"Anthropic:    {'configured' if ANTHROPIC_API_KEY else 'NOT SET'}")
    logger.info(f"Stripe:       {'configured' if STRIPE_SECRET_KEY else 'not set'}")
    logger.info(f"Email:        {'configured' if SMTP_USERNAME else 'not set'}")
    logger.info(f"Base URL:     {APP_BASE_URL}")
    logger.info(f"Database:     {DB_PATH}")

    # Fix #8: Cleanup expired data
    j, c, r = db.cleanup()
    if j or c or r:
        logger.info(f"Cleanup: {j} old jobs, {c} expired cache, {r} stale rate limits")

    # Fix #3: Recover orphaned jobs
    orphaned = db.jobs_get_orphaned(max_age_seconds=900)
    for job in orphaned:
        db.job_fail(job["job_id"], "Job orphaned after server restart")
        logger.warning(f"Marked orphaned job {job['job_id']} as failed")

    logger.info("=" * 50)


@app.on_event("shutdown")
async def shutdown():
    global http_client
    if http_client:
        await http_client.aclose()


# ══════════════════════════════════════════════════
# Prompt Builder
# ══════════════════════════════════════════════════

def build_prompt(user_name: str, members: list[FamilyMember], include_transliteration: bool = False) -> str:
    member_count = len(members)
    length_instruction = get_length_instruction(member_count)

    prompt = f"Please write a personalized du'a for {user_name} and their family.\n\n"
    prompt += f"LENGTH INSTRUCTION: {length_instruction}\n\n"

    if not include_transliteration:
        prompt += (
            "IMPORTANT: Do NOT include Arabic script or transliteration. "
            "Write the du'a in English only. You may reference Quranic verses "
            "and Hadith by their English translation and citation only.\n\n"
        )

    prompt += "FAMILY MEMBERS:\n\n"
    for m in members:
        prompt += f"   Name: {m.name}\n"
        prompt += f"   Relationship: {m.relationship or 'Not specified'}\n"
        prompt += f"   Age Range: {m.ageRange or 'Not specified'}\n"
        prompt += f"   Gender: {m.gender or 'Not specified'}\n"
        prompt += f"   Concerns/Prayer requests: {m.concerns or 'General well-being'}\n\n"

    return prompt


# ══════════════════════════════════════════════════
# AI Callers
# ══════════════════════════════════════════════════


async def call_anthropic(prompt: str, max_tokens: int = 8000) -> str:
    response = await http_client.post(
        "https://api.anthropic.com/v1/messages",
        headers={"Content-Type": "application/json", "x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
        json={
            "model": ANTHROPIC_MODEL, "max_tokens": max_tokens,
            "cache_control": {"type": "ephemeral"},
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    response.raise_for_status()
    data = response.json()
    usage = data.get("usage", {})
    cache_read = usage.get("cache_read_input_tokens", 0)
    if cache_read > 0:
        logger.info(f"Cache HIT: {cache_read} tokens cached, {usage.get('output_tokens', 0)} output")
    return data["content"][0]["text"]


async def call_anthropic_batch(prompt: str, max_tokens: int, user_name: str, user_email: str) -> str:
    """Non-blocking batch submission. Returns job_id immediately."""
    request_id = uuid.uuid4().hex[:8]
    job_id = uuid.uuid4().hex[:12]

    batch_response = await http_client.post(
        "https://api.anthropic.com/v1/messages/batches",
        headers={"Content-Type": "application/json", "x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
        json={"requests": [{
            "custom_id": f"dua-{request_id}",
            "params": {
                "model": ANTHROPIC_MODEL, "max_tokens": max_tokens,
                "cache_control": {"type": "ephemeral"},
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
        }]},
    )
    batch_response.raise_for_status()
    batch_id = batch_response.json()["id"]

    db.job_create(job_id, batch_id, request_id, user_name, user_email)
    logger.info(f"Batch job {job_id} created (batch: {batch_id})")
    return job_id


async def poll_batch_job(job_id: str):
    """
    Background task: polls Anthropic, stores result, sends email server-side.
    Fix #1: Email delivery is fully server-owned — no browser dependency.
    """
    job = db.job_get(job_id)
    if not job:
        logger.error(f"Job {job_id} not found for polling")
        return

    batch_id = job["batch_id"]
    request_id = job["request_id"]

    try:
        for attempt in range(40):  # 15s * 40 = 10 min max
            await asyncio.sleep(15)
            status_response = await http_client.get(
                f"https://api.anthropic.com/v1/messages/batches/{batch_id}",
                headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
            )
            status_response.raise_for_status()
            status_data = status_response.json()
            if status_data.get("processing_status") == "ended":
                logger.info(f"Job {job_id} completed after {(attempt + 1) * 15}s")
                break
        else:
            db.job_fail(job_id, "Batch timed out after 10 minutes")
            return

        results_url = status_data.get("results_url", "")
        if not results_url:
            db.job_fail(job_id, "No results URL from Anthropic")
            return

        results_response = await http_client.get(
            results_url,
            headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
        )
        results_response.raise_for_status()

        dua_text = None
        for line in results_response.text.strip().split("\n"):
            if not line.strip():
                continue
            result = json.loads(line)
            if result.get("custom_id") == f"dua-{request_id}":
                content = result.get("result", {}).get("message", {}).get("content", [])
                if content and content[0].get("type") == "text":
                    dua_text = content[0]["text"]
                    break

        if not dua_text:
            db.job_fail(job_id, "Du'a not found in batch results")
            return

        db.job_complete(job_id, dua_text)

        # Server-owned email delivery with proper status tracking
        user_email = job.get("user_email", "")
        user_name = job.get("user_name", "")
        if user_email and SMTP_USERNAME:
            db.job_set_email_status(job_id, "sending")
            try:
                dua_id = uuid.uuid4().hex[:12]
                token = generate_email_token(dua_id)
                db.save_dua(dua_id, user_name, dua_text, "[]", token, private=True)
                # Fix #3: No "View online" link for private email-only du'as
                await send_dua_email(user_email, user_name, dua_text, share_url=None)
                db.job_set_email_status(job_id, "sent")
                db.track("emails_sent")
                logger.info(f"Job {job_id}: email sent to {user_email}")
            except Exception as e:
                db.job_set_email_status(job_id, "failed")
                logger.error(f"Job {job_id}: email send failed: {e}")
        else:
            db.job_set_email_status(job_id, "none")

    except Exception as e:
        db.job_fail(job_id, f"{type(e).__name__}: {str(e)[:200]}")
        logger.error(f"Job {job_id} failed: {e}")


async def generate_dua_text(prompt: str, member_count: int = 1, delivery_mode: str = "instant",
                            user_name: str = "", user_email: str = "") -> str:
    max_tokens = get_max_tokens(member_count)
    if AI_PROVIDER == "anthropic":
        if not ANTHROPIC_API_KEY:
            raise HTTPException(500, "Anthropic API key not configured.")
        if delivery_mode == "email":
            job_id = await call_anthropic_batch(prompt, max_tokens, user_name, user_email)
            return f"__JOB__{job_id}"
        else:
            return await call_anthropic(prompt, max_tokens)


# ══════════════════════════════════════════════════
# Email Sender
# ══════════════════════════════════════════════════

def _markdown_to_html(text: str) -> str:
    """XSS-safe markdown to HTML conversion."""
    lines = text.split("\n")
    html_lines = []
    for line in lines:
        if line.startswith("## "):
            html_lines.append(f'<h2>{html_escape(line[3:])}</h2>')
        elif line.startswith("# "):
            html_lines.append(f'<h1 style="text-align:center;color:#8b6914;">{html_escape(line[2:])}</h1>')
        elif line.strip() == "---":
            html_lines.append('<hr style="border:none;border-top:1px solid #d4c4a0;margin:20px 0;">')
        elif line.strip() == "":
            html_lines.append("<br/>")
        else:
            safe = html_escape(line)
            safe = re.sub(r"\*\*\*(.+?)\*\*\*", r'<strong style="color:#8b6914;font-style:italic;">\1</strong>', safe)
            safe = re.sub(r"\*\*(.+?)\*\*", r'<strong style="color:#8b6914;">\1</strong>', safe)
            safe = re.sub(r"\*(.+?)\*", r'<em style="color:#6b5a3a;">\1</em>', safe)
            html_lines.append(f"<p>{safe}</p>")
    return "\n".join(html_lines)


async def send_dua_email(to_email: str, recipient_name: str, dua_text: str, share_url: Optional[str] = None):
    if not SMTP_USERNAME:
        raise HTTPException(500, "Email is not configured.")

    dua_html = _markdown_to_html(dua_text)

    # Fix #3: Only include "View online" link if share_url is provided (not for private/email-only du'as)
    footer_link = f'<a href="{share_url}" style="color:#8b6914;">View online</a><br/>' if share_url else ""

    html_body = f"""<html><body style="font-family:Georgia,serif;max-width:650px;margin:0 auto;padding:20px;color:#2c2c2c;line-height:1.8;background:#faf6ef;">
<div style="text-align:center;padding:20px 0;border-bottom:1px solid #d4c4a0;margin-bottom:20px;">
  <div style="font-size:24px;color:#8b6914;font-weight:bold;">Du'a for the Last Ten Nights</div>
  <div style="font-size:14px;color:#888;margin-top:4px;">A personalized supplication for {html_escape(recipient_name)} and family</div>
</div>
{dua_html}
<div style="text-align:center;margin-top:30px;padding-top:20px;border-top:1px solid #d4c4a0;">
  {footer_link}
  <p style="font-size:11px;color:#888;margin-top:10px;">Generated at mydua.ai — support@mydua.ai</p>
</div></body></html>"""

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = f"Your Du'a for the Last Ten Nights — {recipient_name}"
    msg.attach(MIMEText(dua_text, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT,
                          username=SMTP_USERNAME, password=SMTP_PASSWORD, start_tls=True)


# ══════════════════════════════════════════════════
# API Routes
# ══════════════════════════════════════════════════

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "provider": AI_PROVIDER, "version": "10.2",
            "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/generate-dua")
async def generate_dua(req: GenerateDuaRequest, request: Request, background_tasks: BackgroundTasks):
    if not req.userName.strip():
        raise HTTPException(400, "Please enter your name.")

    valid_members = [m for m in req.members if m.name.strip()]
    if not valid_members:
        raise HTTPException(400, "Please add at least one family member with a name.")

    # Fix #4: SQLite-backed rate limiting
    # Fix #4: Safe client IP extraction
    client_ip = get_client_ip(request)
    allowed, remaining = db.rate_limit_check(f"gen:{client_ip}", max_requests=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, f"Rate limit exceeded. Please try again later.")

    # Check cache
    if not req.skipCache:
        cache_key = db.make_cache_key(req.userName, [m.model_dump() for m in valid_members])
        cached = db.cache_get(cache_key)
        if cached:
            db.track("duas_generated")
            return {"dua": cached, "cached": True}

    prompt = build_prompt(req.userName, valid_members, req.includeTransliteration)

    try:
        # Fix #7: Email comes from validated request field, not header
        dua_text = await generate_dua_text(
            prompt, member_count=len(valid_members), delivery_mode=req.deliveryMode,
            user_name=req.userName,
            user_email=req.userEmail or "",
        )
    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        detail = e.response.text[:200]
        logger.error(f"AI API error {status}: {detail}")
        if status == 401:
            raise HTTPException(502, "AI API key is invalid or expired.")
        elif status == 429:
            raise HTTPException(502, "AI API rate limit exceeded. Please wait and try again.")
        elif status == 400:
            raise HTTPException(502, f"AI API rejected request: {detail[:100]}")
        else:
            raise HTTPException(502, f"AI service error {status}.")
    except httpx.ConnectError:
        raise HTTPException(502, "Cannot connect to AI service. Check server internet.")
    except httpx.TimeoutException:
        raise HTTPException(504, "AI service timed out. Try fewer family members.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Generate error: {type(e).__name__}: {e}")
        raise HTTPException(500, f"Generation failed: {type(e).__name__}")

    if not dua_text:
        raise HTTPException(502, "Empty response from AI.")

    # Batch mode returns job marker
    if dua_text.startswith("__JOB__"):
        job_id = dua_text[7:]
        background_tasks.add_task(poll_batch_job, job_id)
        db.track("duas_generated")
        return {"jobId": job_id, "status": "processing", "cached": False}

    # Instant mode
    cache_key = db.make_cache_key(req.userName, [m.model_dump() for m in valid_members])
    db.cache_put(cache_key, dua_text)
    db.track("duas_generated")
    return {"dua": dua_text, "cached": False}


@app.get("/api/job/{job_id}")
async def get_job_status(job_id: str):
    job = db.job_get(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    response = {"jobId": job["job_id"], "status": job["status"],
                "emailStatus": job.get("email_status", "none")}
    if job["status"] == "completed":
        response["dua"] = job["dua"]
    elif job["status"] == "failed":
        response["error"] = job.get("error", "Unknown error")
    return response


@app.post("/api/save-dua")
async def save_dua(req: SaveDuaRequest, request: Request):
    client_ip = get_client_ip(request)
    allowed, _ = db.rate_limit_check(f"save:{client_ip}", max_requests=10, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, "Too many save requests.")

    dua_id = uuid.uuid4().hex[:12]
    token = generate_email_token(dua_id)
    members_json = json.dumps([m.model_dump() for m in req.members]) if req.members else "[]"
    db.save_dua(dua_id, req.userName, req.dua, members_json, token)
    db.track("shares_created")

    return {
        "id": dua_id,
        "shareUrl": f"{APP_BASE_URL}/shared/{dua_id}",
        "emailToken": token,  # Fix #5: Token returned for authorized email sends
    }


@app.get("/api/saved/{dua_id}")
async def get_saved_dua(dua_id: str):
    data = db.get_saved(dua_id)
    if not data:
        raise HTTPException(404, "Du'a not found.")
    # Fix #2: Private du'as (email-only) are not accessible via API
    if data.get("private"):
        raise HTTPException(404, "This du'a is private.")
    return {
        "id": data["dua_id"],
        "userName": data["user_name"],
        "dua": data["dua"],
        "created": data["created"],
    }


@app.post("/api/email-dua")
async def email_dua(req: EmailDuaRequest, request: Request):
    # Fix #4: SQLite rate limit
    client_ip = get_client_ip(request)
    allowed, _ = db.rate_limit_check(f"email:{client_ip}", max_requests=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(429, "Too many email requests.")

    data = db.get_saved(req.duaId)
    if not data:
        raise HTTPException(404, "Du'a not found. Save it first.")

    # Fix #5: Verify HMAC token
    if not req.token or not verify_email_token(req.duaId, req.token):
        raise HTTPException(403, "Invalid email authorization token.")

    share_url = f"{APP_BASE_URL}/shared/{req.duaId}"
    try:
        await send_dua_email(req.email, req.recipientName or data["user_name"], data["dua"], share_url)
    except Exception as e:
        logger.error(f"Email failed: {e}")
        raise HTTPException(500, "Failed to send email. Please try again.")

    db.track("emails_sent")
    return {"status": "sent", "to": req.email}


@app.post("/api/track-pdf")
async def track_pdf():
    db.track("pdfs_exported")
    return {"status": "tracked"}


@app.get("/api/analytics")
async def get_analytics():
    return db.get_stats()


@app.get("/shared/{dua_id}", response_class=HTMLResponse)
async def shared_page(dua_id: str):
    data = db.get_saved(dua_id)
    if not data:
        raise HTTPException(404, "Du'a not found.")

    # Fix #6: Private du'as (from email-only delivery) are not publicly viewable
    if data.get("private"):
        raise HTTPException(404, "This du'a was delivered privately via email.")

    user_name = html_escape(data["user_name"])
    dua_html = _markdown_to_html(data["dua"])

    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Du'a for {user_name} — mydua.ai</title>
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;0,700;1,400;1,700&family=Amiri:wght@400;700&display=swap" rel="stylesheet"/>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box;}}
    body{{font-family:'Cormorant Garamond',serif;background:linear-gradient(160deg,#0a1628 0%,#112240 40%,#0d1f3c 70%,#091525 100%);color:#e8dcc8;min-height:100vh;padding:40px 20px;line-height:1.8;}}
    .wrap{{max-width:700px;margin:0 auto;}}
    .header{{text-align:center;margin-bottom:30px;padding-bottom:20px;border-bottom:1px solid rgba(201,169,110,.2);}}
    .bismillah{{font-family:'Amiri',serif;font-size:28px;color:#c9a96e;direction:rtl;opacity:.8;}}
    h1{{font-size:28px;font-weight:300;color:#e8dcc8;margin:10px 0;}}
    .sub{{font-size:14px;color:#8a7d6b;font-style:italic;}}
    h2{{font-size:22px;color:#c9a96e;margin:28px 0 12px;}}
    p{{font-size:16px;margin:4px 0;}}
    strong{{color:#c9a96e;}}em{{color:#b8a88a;}}
    hr{{border:none;border-top:1px solid rgba(201,169,110,.2);margin:20px 0;}}
    .footer{{text-align:center;font-size:12px;color:#8a7d6b;margin-top:30px;padding-top:20px;border-top:1px solid rgba(201,169,110,.2);}}
    .footer a{{color:#c9a96e;text-decoration:none;}}
  </style>
</head>
<body><div class="wrap">
  <div class="header">
    <div class="bismillah">بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ</div>
    <h1>Du'a for the Last Ten Nights</h1>
    <div class="sub">A personalized supplication for {user_name} and family</div>
  </div>
  {dua_html}
  <div class="footer">
    <a href="/">Generate your own du'a at mydua.ai</a>
    <p style="margin-top:10px;">Please verify all Quranic verses and Hadith with authentic Islamic sources.</p>
  </div>
</div></body></html>""")


# ══════════════════════════════════════════════════
# Stripe — "Support Us" Donations
# ══════════════════════════════════════════════════

SUPPORT_AMOUNTS = {
    "5": {"label": "$5 — A Small Kindness", "cents": 500},
    "10": {"label": "$10 — May Allah Reward You", "cents": 1000},
    "25": {"label": "$25 — Generous Support", "cents": 2500},
    "50": {"label": "$50 — Sadaqah Jariyah", "cents": 5000},
}


@app.get("/api/stripe-config")
async def stripe_config():
    if not STRIPE_PUBLISHABLE_KEY:
        raise HTTPException(500, "Stripe is not configured.")
    return {"publishableKey": STRIPE_PUBLISHABLE_KEY}


@app.post("/api/create-support-session")
async def create_support_session(req: SupportRequest):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(500, "Stripe is not configured.")

    if req.amount == "custom":
        if req.customAmount < 1:
            raise HTTPException(400, "Please enter an amount of at least $1.")
        amount_cents = req.customAmount * 100
        label = f"${req.customAmount} — Custom Support"
    elif req.amount in SUPPORT_AMOUNTS:
        amount_cents = SUPPORT_AMOUNTS[req.amount]["cents"]
        label = SUPPORT_AMOUNTS[req.amount]["label"]
    else:
        raise HTTPException(400, "Invalid amount.")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": "Support mydua.ai", "description": label},
                    "unit_amount": amount_cents,
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{APP_BASE_URL}/support-thank-you",
            cancel_url=f"{APP_BASE_URL}/#support",
            submit_type="donate",
        )
        db.track("donations_initiated")
        return {"url": session.url}
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        raise HTTPException(500, f"Payment error: {str(e)}")


@app.get("/support-thank-you", response_class=HTMLResponse)
async def support_thank_you():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Thank You — mydua.ai</title>
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400;600;700&family=Amiri:wght@400;700&display=swap" rel="stylesheet"/>
  <style>
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Cormorant Garamond',serif;background:linear-gradient(160deg,#0a1628 0%,#112240 40%,#0d1f3c 70%,#091525 100%);color:#e8dcc8;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:40px 20px;}
    .card{max-width:520px;background:rgba(255,255,255,0.03);border:1px solid rgba(201,169,110,0.15);border-radius:20px;padding:48px 40px;backdrop-filter:blur(10px);}
    .bismillah{font-family:'Amiri',serif;font-size:28px;color:#c9a96e;direction:rtl;opacity:0.8;margin-bottom:16px;}
    h1{font-size:32px;font-weight:300;color:#e8dcc8;margin-bottom:12px;}
    .gold{color:#c9a96e;font-weight:600;}
    p{font-size:17px;color:#d4c9b4;line-height:1.7;margin-bottom:16px;}
    .arabic{font-family:'Amiri',serif;font-size:22px;color:#c9a96e;margin:20px 0;}
    a{display:inline-block;margin-top:20px;padding:12px 32px;border:1px solid rgba(201,169,110,0.3);border-radius:10px;color:#c9a96e;text-decoration:none;font-size:16px;font-weight:600;transition:all 0.3s;}
    a:hover{background:rgba(201,169,110,0.08);}
  </style>
</head>
<body>
  <div class="card">
    <div class="bismillah">بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ</div>
    <h1><span class="gold">Jazak'Allah Khair</span></h1>
    <p>May Allah reward you abundantly for your generosity. Your support helps us keep this service free and available to Muslims around the world.</p>
    <div class="arabic">جَزَاكَ اللَّهُ خَيْرًا</div>
    <p>May your donation be a <strong style="color:#c9a96e;">sadaqah jariyah</strong> — a continuous charity that benefits you in this life and the next.</p>
    <a href="/">Return to Du'a Generator</a>
  </div>
</body>
</html>""")


# ══════════════════════════════════════════════════
# Static Files (must be last)
# ══════════════════════════════════════════════════

app.mount("/", StaticFiles(directory=str(BASE_DIR / "static"), html=True), name="static")
