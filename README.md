# Securing User Data in Web Applications

Security-focused Django demo app for an academic course. It demonstrates practical controls for authentication, secure data handling, attack mitigation, and security monitoring.

## Current Feature Set

### Core security controls
- Email-based authentication (custom user model, no username field).
- Password hashing via Django defaults (`pbkdf2_sha256`).
- CSRF protection on forms.
- Sensitive profile fields encrypted at rest (Fernet).
- Brute-force protection with `django-axes` plus app-level CAPTCHA gate.
- Security event logging and staff-only security dashboard.
- Strict session and browser security headers.

### Login protection policy (current)
- After repeated failed logins, user is redirected to a dedicated CAPTCHA step.
- Failed attempts are tracked by normalized email in cache for deterministic behavior.
- CAPTCHA challenge is time-limited and grants limited additional attempts after success.
- Account lockout activates after threshold and lasts 30 minutes.

### User-facing pages
- Home and Security Tips pages (public).
- Security Demo page (public) with visual evidence of controls.
- Profile dashboard (authenticated users).
- Security monitoring dashboard (staff only): `/security/dashboard/`.
- Health check endpoint: `/healthz/`.

## Tech Stack
- Django 4.2
- Python 3.11+
- PostgreSQL in production via `DATABASE_URL`; SQLite fallback for local development
- Tailwind (CDN) with Django templates
- `django-axes`, `cryptography`, `whitenoise`, `dj-database-url`

## Quick Start

1. Create and activate venv.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create `.env` from `sample.env.example` and set:
   - `DJANGO_SECRET_KEY`
   - `ENCRYPTION_KEY`
   - `DEBUG`
   - `ALLOWED_HOSTS`
   - `CSRF_TRUSTED_ORIGINS`
4. Apply migrations:
   ```bash
   python manage.py migrate
   ```
5. Create admin user:
   ```bash
   python manage.py createsuperuser
   ```
6. Run app:
   ```bash
   python manage.py runserver
   ```

## Tests
```bash
python manage.py test
```

## Notes
- Keep all secrets only in environment variables.
- Verification endpoints are preserved for reversibility, but the current registration flow activates users immediately.
