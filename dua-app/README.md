# Du'a Generator — Last 10 Nights of Ramadan

A web application that generates personalized Islamic supplications (du'as) for families to recite during the blessed last 10 nights of Ramadan.

## Features

- **AI-Powered Du'a Generation** — Uses OpenAI GPT-4o or Anthropic Claude to create deeply personal, Quran-and-Hadith-rich supplications
- **Multi-Language** — Arabic transliteration alongside English so users can recite in Arabic
- **PDF Export** — Download beautifully formatted PDF via html2pdf.js
- **Email Delivery** — Send the du'a directly to any email address
- **Shareable Links** — Generate a unique URL to share with family and friends
- **Anonymous Analytics** — Track total du'as generated (no personal data collected)
- **Smart Caching** — Cache identical requests to reduce API costs
- **Rate Limiting** — Prevent abuse (5 du'a generations/hour, 10 saves/hour, 5 emails/hour per IP)

## Tech Stack

- **Backend:** Python 3.11+ / FastAPI
- **AI:** OpenAI GPT-4o or Anthropic Claude
- **Frontend:** Vanilla HTML/CSS/JS (single file, no build step)
- **PDF:** html2pdf.js (client-side)
- **Email:** aiosmtplib (async SMTP)
- **Storage:** File-based JSON (no database required)

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/your-username/dua-generator.git
cd dua-generator

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your API keys and SMTP settings

# 4. Run the server
uvicorn app:app --reload --port 8000

# 5. Open http://localhost:8000
```

## Project Structure

```
dua-app/
├── app.py              ← FastAPI backend (all API routes)
├── requirements.txt    ← Python dependencies
├── .env.example        ← Environment variable template
├── README.md           ← This file
├── static/
│   └── index.html      ← Complete frontend (single file)
└── data/               ← Auto-created at runtime
    ├── analytics.json   ← Anonymous usage counters
    ├── cache/           ← Cached AI responses
    └── saved/           ← Saved/shared du'as
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/health` | Health check |
| `POST` | `/api/generate-dua` | Generate a personalized du'a |
| `POST` | `/api/save-dua` | Save du'a and get shareable URL |
| `GET`  | `/api/saved/{id}` | Retrieve a saved du'a |
| `POST` | `/api/email-dua` | Email a saved du'a |
| `POST` | `/api/track-pdf` | Track PDF export (analytics) |
| `GET`  | `/api/analytics` | Get anonymous usage stats |
| `GET`  | `/shared/{id}` | View shared du'a (HTML page) |

## Configuration

### AI Provider

Set `AI_PROVIDER` in `.env` to either `openai` or `anthropic`, then provide the corresponding API key.

### Email (Gmail)

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password: https://support.google.com/accounts/answer/185833
3. Use that App Password as `SMTP_PASSWORD`

### Deployment

**Vercel:** Not ideal for FastAPI (use for frontend-only deployments)

**Railway / Render / Fly.io (Recommended):**
1. Push to GitHub
2. Connect repo in Railway/Render dashboard
3. Set environment variables
4. Connect your domain
5. Deploy

**VPS (DigitalOcean, AWS, etc.):**
```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```
Use nginx as reverse proxy + Let's Encrypt for SSL.

## Cost Estimates

| Component | Monthly Cost |
|-----------|-------------|
| Hosting (Railway free tier) | $0-5 |
| Domain | ~$1/mo |
| Anthropic API (Opus 4.6, ~100 du'as/day for 10 days) | ~$30-45 total |
| Email (Gmail) | Free |

## Production Deployment Notes

**This app is designed for single-instance deployment** (e.g., Railway with a persistent volume, a single DigitalOcean droplet, or Render). The following design decisions are intentional tradeoffs for simplicity at this scale:

- **SQLite database**: All data (cache, jobs, saved du'as, analytics, rate limits) is stored in a single `data/mydua.db` file. SQLite with WAL mode handles concurrent reads safely and is the correct choice for a single-instance app. If you need to scale to multiple instances, migrate to PostgreSQL.

- **Background tasks**: Batch du'a generation uses FastAPI's `BackgroundTasks` which is process-local. If the server restarts during the 2-5 minute window a batch is processing, that job is marked as failed on the next startup. Users see a clear error and can retry. For higher durability, migrate to Celery + Redis.

- **Rate limiting**: Stored in SQLite, survives restarts, but is per-instance. If running multiple instances behind a load balancer, migrate to Redis-backed rate limiting.

**Production checklist:**
- [ ] Set `APP_ENV=production` (the app refuses to start with the default SECRET_KEY in production)
- [ ] Set a real `SECRET_KEY` (at least 32 random characters)
- [ ] Use live Stripe keys (`sk_live_...`, `pk_live_...`)
- [ ] Set `APP_BASE_URL` to your domain (`https://mydua.ai`)
- [ ] Configure SMTP credentials for email delivery
- [ ] Mount a persistent volume at the `data/` directory (Railway: Settings → Volumes)
- [ ] Run with a single instance (do NOT scale to multiple replicas without migrating to PostgreSQL + Redis)

---

*May Allah accept the du'as of all who use this tool. Ameen.*
