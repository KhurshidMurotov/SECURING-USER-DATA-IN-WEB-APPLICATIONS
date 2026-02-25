# Deployment Checklist

## 1) Overview
This project is a Django security-focused demo application (email-based auth, verification, encrypted profile fields, CSRF, rate limiting, security logging). “Production deployment” here means running it on a real domain with HTTPS, persistent database, and working SMTP, while keeping security settings strict and environment-driven.

## 2) Environment Variables
Set these in your hosting environment (not in source control).

| Variable | Required | Example (safe) | Notes |
|---|---|---|---|
| `DJANGO_SECRET_KEY` | Yes | `change-me-use-long-random-secret` | Use a long random value. |
| `DEBUG` | Yes | `False` | Must be `False` in production. |
| `ALLOWED_HOSTS` | Yes | `example.com,www.example.com` | Comma-separated hostnames. |
| `CSRF_TRUSTED_ORIGINS` | Yes | `https://example.com,https://www.example.com` | Include scheme (`https://`). |
| `DATABASE_URL` | Yes | `postgres://user:pass@db-host:5432/appdb` | Use managed Postgres in production. |
| `ENCRYPTION_KEY` | Yes | `base64-fernet-key-here` | Fernet key (base64, 32-byte key format). |
| `EMAIL_BACKEND` | Yes | `django.core.mail.backends.smtp.EmailBackend` | SMTP backend for real sending. |
| `EMAIL_HOST` | Yes | `smtp.gmail.com` | SMTP host. |
| `EMAIL_PORT` | Yes | `587` | Typically 587 for STARTTLS. |
| `EMAIL_USE_TLS` | Yes | `True` | Use TLS for SMTP transport. |
| `EMAIL_HOST_USER` | Yes | `no-reply@example.com` | SMTP username/account. |
| `EMAIL_HOST_PASSWORD` | Yes | `app-password-or-smtp-token` | Never commit this. |
| `DEFAULT_FROM_EMAIL` | Yes | `no-reply@example.com` | Sender address users see. |

## 3) SMTP Nuances (Important)
- In hosting, outgoing SMTP uses your hosting provider’s IP, not your local machine IP.
- Effects you may see:
  - Emails landing in spam.
  - Provider-side SMTP blocks or rate limits.
  - “Suspicious login” alerts from mailbox provider.
- Troubleshooting runbook:
  1. Verify SMTP port `587` is allowed by hosting/network firewall.
  2. Confirm `EMAIL_USE_TLS=True` and that TLS negotiation succeeds.
  3. Verify credentials (for Gmail: app password, not normal account password).
  4. Check hosting logs and SMTP provider logs for auth/connection errors.
  5. Send one test email first (single recipient), then test app registration flow.
- Recommendation:
  - Coursework/demo: SMTP mailbox is acceptable.
  - Serious production: use a transactional email provider (SES, SendGrid, Mailgun, Postmark).

## 4) Domain/HTTPS Nuances
- Set `ALLOWED_HOSTS` to your exact deployed hostnames.
- Set `CSRF_TRUSTED_ORIGINS` to full HTTPS origins (with `https://`).
- Ensure TLS certificate is valid and app is served over HTTPS.
- Email verification links are built from request host. If reverse proxy is used, make sure host/proto forwarding is correct so links use the real public domain.

## 5) Static Files Checklist
- Run static collection on deploy:
  - `python manage.py collectstatic --noinput`
- WhiteNoise:
  - This project currently does **not** include WhiteNoise.
  - If your platform does not serve static files automatically, configure platform static serving or add WhiteNoise explicitly.
- Verify after deploy:
  - Open home page and confirm CSS/styles load.
  - Check browser network tab for 200 responses on static assets (no 404/403).

## 6) Database & Migrations Checklist
- Apply migrations on every deploy:
  - `python manage.py migrate`
- Create admin user (once):
  - `python manage.py createsuperuser`
- Sanity-check key tables exist and are readable:
  - `accounts_user`
  - `profiles_userprofile`
  - `security_securityevent`

## 7) Post-Deploy Verification Steps
1. Open `/security-demo/` and confirm all sections load.
2. Register a new account and confirm verification email is delivered.
3. Verify login protection flow (failed logins -> CAPTCHA -> lockout behavior).
4. Confirm encryption-at-rest by checking DB value in `profiles_userprofile` (should look like `gAAAAA...`, not plaintext).
5. Confirm CSRF behavior: missing token on POST returns HTTP 403.
6. Confirm security dashboard access is staff-only (`/security/dashboard/`).

## Quick Sanity Checklist
- [ ] `DEBUG=False`
- [ ] Correct `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`
- [ ] SMTP works from hosting environment
- [ ] `collectstatic` completed and static assets load
- [ ] Migrations applied successfully
- [ ] Superuser/staff access configured
- [ ] Registration + email verification works end-to-end
- [ ] CAPTCHA/lockout behavior works
- [ ] Encryption-at-rest and CSRF checks validated
