# SecureSBOM — Deployment Guide (Local & Production)

## 1. Prerequisites
- Python 3.12+ or 3.13
- Node.js 18+ and npm
- (Optional for production) Docker & Docker Compose, PostgreSQL 16, Nginx/Caddy with TLS certificates

## 2. Local Development Setup (Windows & Linux)
### Backend
```powershell
# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt -r backend/requirements.txt
pip install argon2-cffi PyJWT cryptography defusedxml scikit-learn alembic slowapi reportlab pydantic-settings email-validator

copy .env.example .env
# Edit .env and set SECRET_KEY and ENCRYPTION_KEY
alembic upgrade head
uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173`. Register a user at `/login` (the first registered user is assigned `admin`, subsequent users get `user`).

## 3. Production Deployment (Docker Compose + PostgreSQL + Nginx)
1. Generate production keys:
```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```
2. Export `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, and `CORS_ORIGINS` (e.g., `https://securesbom.yourdomain.com`).
3. Start the stack:
```bash
docker compose up -d --build
```
4. Terminate HTTPS in front of Nginx (port 80/443) using Certbot/Let's Encrypt or Caddy, and set `COOKIE_SECURE=true`.

## 4. No-AI vs Optional Local AI
- **No-AI Mode (Default):** `AI_ENABLED=False`. Deterministic OSV/NVD/KEV/EPSS scanning and evidence-synthesis RAG work with zero external AI keys or GPU.
- **Local Ollama / llama.cpp:** Set `AI_ENABLED=True`, `AI_PROVIDER=ollama`, `AI_BASE_URL=http://localhost:11434/v1`, `AI_MODEL_NAME=llama3.2`.
