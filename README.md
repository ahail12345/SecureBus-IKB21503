# 🛡️ SecureBus — Secure Bus Booking System

**Course:** IKB21503 Secure Software Development  
**Framework:** Django 5.1 (Python)  
**Security Standards:** OWASP Top 10 | OWASP ASVS | SSDF | Secure Coding Best Practices

---

## 📋 Project Description

SecureBus is an OWASP-compliant web application for bus ticket booking. It demonstrates secure software development practices including injection-free coding, role-based access control, audit logging, and defence-in-depth security controls.

---

## 🔐 Security Features Summary

| Control | Implementation |
|---|---|
| Input Validation | Regex whitelisting, Django forms, server-side only |
| Authentication | bcrypt hashing, session timeout, CSRF protection |
| Access Control | RBAC (Admin/User), IDOR prevention via UUID |
| Error Handling | Custom error pages (400/403/404/500), no stack traces |
| Sensitive Data | bcrypt passwords, .env secrets, no plaintext logs |
| File Upload | MIME validation, size limit, UUID rename |
| Config Security | .env file, DEBUG=False, no hardcoded secrets |
| Logging | AuditLog model + rotating file log, no credential logging |
| Dependencies | pip-audit SCA, pinned versions |
| Output Encoding | Django auto-escaping (XSS prevention) |
| Brute Force | django-axes: 5 attempts → 1 hour lockout |
| Security Headers | CSP, X-Frame-Options, X-Content-Type-Options |

---

## ⚙️ Installation Steps

### Prerequisites
- Python 3.12+
- pip
- libmagic (for MIME validation)

```bash
# Install libmagic (Ubuntu/Debian)
sudo apt-get install libmagic1

# macOS
brew install libmagic
```

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/securebus.git
cd securebus

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your settings

# 5. Run migrations
python manage.py migrate

# 6. Create admin user
python manage.py createsuperuser

# 7. Run the application
python manage.py runserver
```

### Access the app
- URL: http://127.0.0.1:8000/
- Admin: http://127.0.0.1:8000/admin/

---

## 👤 Demo Accounts

| Role | Username | Password |
|---|---|---|
| Admin | admin | Admin@Secure123! |
| User | testuser | User@Secure123! |

---

## 📁 Repository Structure

```
securebus/
├── core/                       # Main Django app
│   ├── models.py               # CustomUser, Bus, Booking, AuditLog
│   ├── views.py                # All views with RBAC
│   ├── forms.py                # Input validation forms
│   ├── urls.py                 # URL routing
│   ├── middleware.py           # Security headers + audit middleware
│   ├── decorators.py           # @admin_required, @user_required
│   ├── utils.py                # log_event(), secure_filename()
│   ├── admin.py                # Django admin config
│   └── templates/              # HTML templates
├── secure_booking/
│   ├── settings.py             # Secure Django settings
│   └── urls.py                 # Root URL config + error handlers
├── logs/                       # Security log files (gitignored)
├── media/                      # User uploads (gitignored)
├── .env.example                # Environment template (no real secrets)
├── requirements.txt            # Pinned dependencies
└── README.md
```

---

## 🧪 Running Security Tests

```bash
# SAST — Bandit static analysis
bandit -r core/ -f txt -o reports/bandit_report.txt

# SCA — Dependency vulnerability scan
pip-audit -r requirements.txt -o reports/sca_report.txt

# Run Django checks
python manage.py check --deploy
```

---

## 📦 Dependencies

See `requirements.txt` for full list. Key packages:
- `django` — web framework
- `django-axes` — brute-force protection  
- `bcrypt` — password hashing
- `python-magic` — MIME type file validation
- `django-environ` — .env configuration
- `bandit` — static security analysis
- `pip-audit` — dependency vulnerability scanning

---

## 🛡️ OWASP Top 10 Coverage

| # | Vulnerability | Mitigation |
|---|---|---|
| A01 | Broken Access Control | RBAC decorators, UUID booking refs, ownership checks |
| A02 | Cryptographic Failures | bcrypt, HTTPS, HttpOnly cookies |
| A03 | Injection | Django ORM only, regex input validation |
| A04 | Insecure Design | Threat-modelled RBAC, audit log design |
| A05 | Security Misconfiguration | .env, DEBUG=False, security headers |
| A06 | Vulnerable Components | pip-audit SCA, pinned deps |
| A07 | Auth Failures | django-axes lockout, session timeout |
| A08 | Software Integrity | Verified PyPI packages |
| A09 | Logging Failures | AuditLog model, rotating file log |
| A10 | SSRF | No external URL fetching from user input |
