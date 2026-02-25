# Securing User Data in Web Applications

A complete, secure, student-friendly web application prototype demonstrating best practices for protecting user data in a modern web environment.

## Features

### Security Features
- ✅ **Secure Authentication**: Email-based login with strong password validation (PBKDF2 hashing)
- ✅ **Rate Limiting**: Brute-force protection via django-axes (5 attempts, 1-hour lockout)
- ✅ **Encrypted Storage**: Field-level encryption for sensitive data (address, notes) using Fernet-based authenticated symmetric encryption
- ✅ **Secure Sessions**: HTTP-only cookies, secure flags, 30-minute expiration
- ✅ **CSRF Protection**: Enabled on all forms
- ✅ **Security Headers**: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc.
- ✅ **Audit Logging**: Comprehensive security event logging
- ✅ **Security Dashboard**: Admin-only monitoring dashboard

### Application Features
- User registration and login
- User profile management with encrypted fields
- Security tips educational page
- Modern responsive UI with Tailwind CSS

## Tech Stack

- **Backend**: Django 4.2 LTS, Python 3.9+ (Django 4.2 LTS was selected for stability and long-term support)
- **Database**: PostgreSQL (SQLite for local development)
- **Frontend**: Django Templates + Tailwind CSS (via CDN for simplicity)
- **Security**: django-axes, cryptography

## Setup Instructions

### Prerequisites
- Python 3.11 or higher
- PostgreSQL (optional, SQLite works for local development)
- pip

### Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd SECURING-USER-DATA-IN-WEB-APPLICATIONS
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   ```bash
   cp sample.env.example .env
   ```
   
   Edit `.env` and set the following:
   - `DJANGO_SECRET_KEY`: Generate with `openssl rand -hex 32`
   - `ENCRYPTION_KEY`: Generate with:
     ```python
     python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
     ```
   - `DATABASE_URL`: PostgreSQL connection string (or leave default for SQLite)
   - `DEBUG`: Set to `True` for development
   - `ALLOWED_HOSTS`: Comma-separated list of allowed hosts

5. **Run migrations:**
   ```bash
   python manage.py migrate
   ```

6. **Create a superuser:**
   ```bash
   python manage.py createsuperuser
   ```
   (Use email as username)

7. **Run the development server:**
   ```bash
   python manage.py runserver
   ```

8. **Access the application:**
   - Home: http://127.0.0.1:8000/
   - Admin: http://127.0.0.1:8000/admin/
   - Security Dashboard: http://127.0.0.1:8000/security/dashboard/ (staff only)

## Running Tests

```bash
python manage.py test
```

Tests cover:
- User registration and login flows
- Encrypted fields (verify encryption at rest)
- CSRF protection
- Rate limiting
- Permission restrictions
- Security event logging

## Project Structure

```
secure_web/
├── manage.py
├── requirements.txt
├── .env (create from sample.env.example)
├── secure_web/          # Django project settings
│   ├── settings.py      # Security-focused configuration
│   ├── urls.py
│   └── wsgi.py
├── apps/
│   ├── accounts/        # Custom user model, auth flows
│   ├── profiles/        # Encrypted profile data
│   ├── security/        # Audit logs, middleware, dashboard
│   └── pages/           # Landing, security tips
├── templates/           # Django templates with Tailwind
├── static/              # Static files
└── docs/                # Documentation
    ├── threat_model.md
    └── security_controls.md
```

## Security Configuration

### Encryption Key Management
- The `ENCRYPTION_KEY` must be a base64-encoded 32-byte key (Fernet format)
- Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- **Never commit the encryption key to version control**
- In production, use a key management service (AWS KMS, HashiCorp Vault, etc.)

### Session Security
- Sessions expire after 30 minutes of inactivity
- Cookies are HTTP-only and secure (in production)
- SameSite attribute set to 'Lax' for CSRF protection

### Rate Limiting
- 5 failed login attempts trigger a 1-hour lockout
- Lockout is per IP + username combination
- Reset on successful login

## Development Notes

- **No React**: This project uses Django templates only
- **Tailwind CSS**: Included via CDN for simplicity (see `templates/base.html`)
- **No external services**: All functionality is self-contained
- **Demo data only**: Do not use real personal data beyond local testing

## Documentation

- [Threat Model](docs/threat_model.md) - Assets, threats, and mitigations
- [Security Controls](docs/security_controls.md) - Implementation details

## License

This is an educational project for demonstrating web application security best practices.
