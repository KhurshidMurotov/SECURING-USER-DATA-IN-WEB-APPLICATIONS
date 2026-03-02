# Deployment Checklist

## 1) Overview
This project is a Django security demo app. Production deployment means running with `DEBUG=False`, HTTPS, persistent database, correct static delivery, and stable security controls (CAPTCHA + lockout + logging) under reverse proxy.

## 2) Environment Variables
Set these in Railway/hosting, never in source control.

| Variable | Required | Example (safe) | Notes |
|---|---|---|---|
| `DJANGO_SECRET_KEY` | Yes | `change-me-long-random-secret` | Long random secret. |
| `DEBUG` | Yes | `False` | Must be false in prod. |
| `ALLOWED_HOSTS` | Yes | `example.com,www.example.com` | Comma-separated. |
| `CSRF_TRUSTED_ORIGINS` | Yes | `https://example.com,https://www.example.com` | Include scheme. |
| `DATABASE_URL` | Yes | `postgresql://user:pass@host:5432/db` | Railway Postgres URL. |
| `ENCRYPTION_KEY` | Yes | `base64-fernet-key` | Fernet key for encrypted profile fields. |
| `TRUST_PROXY_HEADERS` | Recommended | `True` | Use forwarded headers behind trusted proxy. |
| `EMAIL_BACKEND` | Optional | `django.core.mail.backends.smtp.EmailBackend` | Use SMTP only if email flow enabled. |
| `EMAIL_HOST` | Optional | `smtp.gmail.com` | SMTP host. |
| `EMAIL_PORT` | Optional | `587` | STARTTLS port. |
| `EMAIL_USE_TLS` | Optional | `True` | TLS for SMTP. |
| `EMAIL_HOST_USER` | Optional | `no-reply@example.com` | SMTP username. |
| `EMAIL_HOST_PASSWORD` | Optional | `app-password` | Secret. |
| `DEFAULT_FROM_EMAIL` | Optional | `no-reply@example.com` | Sender address. |
| `LOGIN_CAPTCHA_THRESHOLD` | Optional | `2` | CAPTCHA starts when attempts >= threshold. |
| `LOGIN_LOCKOUT_THRESHOLD` | Optional | `5` | Lock after this many failed attempts. |
| `LOGIN_LOCKOUT_SECONDS` | Optional | `1800` | 30 minutes. |

## 3) SMTP Nuances
- In hosting, SMTP traffic uses hosting IP, not your local machine IP.
- Possible outcomes: spam placement, provider blocks/rate limits, suspicious-login alerts.
- Troubleshooting:
  1. Verify outbound 587 availability.
  2. Verify TLS (`EMAIL_USE_TLS=True`).
  3. Verify SMTP credentials/app password.
  4. Check provider logs and app logs.
  5. Test single send first.
- Recommendation: for serious production use transactional email (SES/SendGrid/Mailgun/Postmark).

## 4) Domain and HTTPS Nuances
- Set `ALLOWED_HOSTS` to deployed domains.
- Set `CSRF_TRUSTED_ORIGINS` to full HTTPS origins.
- With proxy (Railway), set `TRUST_PROXY_HEADERS=True` so IP/proto parsing is consistent.
- Ensure public domain is used in generated links.

## 5) Static Files Checklist
- WhiteNoise is enabled in settings and middleware.
- Static source: `static/`; build output: `staticfiles/`.
- Required on deploy:
  - `python manage.py collectstatic --noinput`
- Verify after deploy:
  - `/static/admin/css/base.css` returns 200
  - `/static/images/security-demo/1.png` returns 200

## 6) Database and Migrations Checklist
- On deploy run:
  - `python manage.py migrate`
- Create admin user once:
  - `python manage.py createsuperuser`
- Sanity check key tables:
  - `accounts_user`
  - `profiles_userprofile`
  - `security_securityevent`

## 7) Post-Deploy Verification
1. Open `/healthz/` and expect `{"status": "ok"}`.
2. Open `/security-demo/` and verify screenshots/static load.
3. Register user and login flow works without 500 errors.
4. Trigger failed logins: CAPTCHA appears at threshold, lockout occurs at configured limit.
5. Confirm encrypted DB fields in `profiles_userprofile` look like `gAAAAA...`.
6. Confirm CSRF rejection for POST without token (403).
7. Confirm `/security/dashboard/` is staff-only.

## Quick Sanity Checklist
- [ ] `DEBUG=False`
- [ ] Correct `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`
- [ ] `TRUST_PROXY_HEADERS=True` in Railway
- [ ] `collectstatic` executed
- [ ] Static endpoints return 200
- [ ] Migrations applied
- [ ] Security dashboard accessible only by staff
- [ ] CAPTCHA and lockout policy behaves as expected
- [ ] No secrets committed to repo
