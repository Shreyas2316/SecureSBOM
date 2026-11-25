# SecureSBOM (PRJ_56) — Security & Encryption Model

## 1. Authentication & Session Architecture
- **Password Hashing:** Argon2id via `argon2-cffi` (`time_cost=2, memory_cost=65536, parallelism=2`). Plaintext passwords are never stored or logged.
- **Access Tokens:** Short-lived JWTs (`HS256`, default 30 minutes) with unique `jti` claims. Checked against `revoked_tokens` on every authenticated request.
- **Refresh Tokens:** 7-day JWTs persisted in `refresh_tokens` with rotation on `/api/v1/auth/refresh`. Reuse of a revoked refresh token triggers automatic revocation of all active refresh tokens for that user.
- **Transport & Cookies:** Supports both `Authorization: Bearer <token>` and `HttpOnly`, `SameSite=Lax` cookies (`COOKIE_SECURE=True` in production HTTPS).
- **Rate Limiting:** Sliding-window rate limiting on `/api/v1/auth/login`, `/register`, and `/password-reset/request`.

## 2. Authorization & Cross-User Isolation
- **Roles:** `user` and `admin`.
- **Resource Ownership:** `Project`, `Scan`, `EmergingFinding`, `PotentialWeakness`, and `StaticAnalysisResult` bind `owner_id` to `current_user.id`. Non-admin users cannot access or mutate another user's scans, SBOMs, or findings (returns `404` to prevent resource enumeration).
- **No Spoofable Headers:** `X-User-Id` trust has been completely removed from `app/api/ai_routes.py` and `frontend/src/api.js`.

## 3. Encryption & Key Management
- **Field-Level Encryption:** `backend/app/core/encryption.py` uses `cryptography.fernet.MultiFernet` (AES-128-CBC + HMAC-SHA256) to encrypt sensitive user-provided AI API credentials (`users.encrypted_ai_api_key`).
- **Key Rotation Strategy:** `ENCRYPTION_KEY` supports comma-separated Fernet keys (`new_key,old_key`). New writes use the primary (first) key; reads decrypt with any listed key.
- **Database-at-Rest Note:** Field-level encryption protects sensitive credential columns inside SQLite/PostgreSQL; it does **not** encrypt the entire SQLite database file. For full database-at-rest encryption in production, deploy PostgreSQL with encrypted EBS/volume storage or TLS-encrypted managed Postgres.
- **Log Redaction:** `redact_sensitive()` masks Bearer tokens, API keys, and passwords before logging.
- **Security Headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security` (in production).
