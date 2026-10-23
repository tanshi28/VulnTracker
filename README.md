# Vulnerability Tracker

A Django-based web application for tracking CVE vulnerabilities, managing affected systems, profiling threat actors, and running non-intrusive security assessments against authorized web assets.

---

## Features

- **Vulnerability Management** — Log CVEs with severity (Critical / High / Medium / Low), status (Open / In-Progress / Patched), affected system, and optional threat-actor attribution.
- **Threat Actor Profiles** — Maintain records of known threat actors and see which vulnerabilities they are linked to.
- **Affected Systems** — Group vulnerabilities by the system they impact.
- **Dashboard** — At-a-glance counts broken down by severity and remediation status.
- **Web Asset Registry** — Register HTTP/HTTPS targets; explicit authorization gate prevents accidental scanning.
- **Security Assessments** — Run automated, non-intrusive checks (security headers + cookie attributes) against authorized assets and review detailed findings.
- **SSRF Protections** — Every outbound HTTP request is validated for public-only destinations; private IPs, localhost, `.local`, and `.internal` hostnames are blocked.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Django 5.2 |
| Database | SQLite (default) |
| HTTP client | `requests` ≥ 2.32 |
| Testing | pytest + pytest-django |
| Python | 3.11+ |

---

## Project Structure

```
Vulnerability-Tracker/
├── vulntracker/                   # Django project root
│   ├── manage.py
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── db.sqlite3
│   ├── vulntracker/               # Django settings package
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── wsgi.py
│   │   └── asgi.py
│   └── vulnerabilities/           # Main Django application
│       ├── models.py              # Data models
│       ├── views.py               # Request handlers
│       ├── urls.py                # URL routing
│       ├── admin.py               # Django admin registration
│       ├── scanner.py             # URL & DNS validation
│       ├── safe_http.py           # SSRF-safe HTTP transport
│       ├── security_checks.py     # Header & cookie analysis
│       ├── assessment_runner.py   # Assessment orchestration
│       ├── finding_utils.py       # Finding persistence helpers
│       ├── tests.py               # Assessment workflow tests
│       ├── tests_safe_http.py     # Safe HTTP transport tests
│       ├── migrations/            # Database migrations
│       ├── templates/             # HTML templates
│       └── static/                # CSS assets
└── env/                           # Python virtual environment
```

---

## Getting Started

### Prerequisites

- Python 3.11 or newer
- `pip`

### Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd Vulnerability-Tracker

# 2. Create and activate a virtual environment
python -m venv env
# Windows
env\Scripts\activate
# macOS / Linux
source env/bin/activate

# 3. Install dependencies
pip install -r vulntracker/requirements.txt

# 4. Apply database migrations
cd vulntracker
python manage.py migrate

# 5. Create a superuser (for Django admin access)
python manage.py createsuperuser

# 6. Start the development server
python manage.py runserver
```

The application will be available at `http://127.0.0.1:8000/`.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | Insecure dev key | Secret key used for signing sessions and tokens. **Must be set in production.** |
| `DJANGO_DEBUG` | `True` | Set to `False` in production. |
| `DJANGO_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Comma-separated list of allowed host headers. |

Example `.env` usage:

```bash
export DJANGO_SECRET_KEY="your-strong-random-key"
export DJANGO_DEBUG="False"
export DJANGO_ALLOWED_HOSTS="yourdomain.com"
```

---

## URL Routes

| URL | View | Description |
|---|---|---|
| `/` | `home` | Homepage with recent & critical vulnerabilities |
| `/dashboard/` | `dashboard` | Summary counts by severity and status |
| `/vulnerabilities/` | `vuln_list` | Filterable vulnerability list |
| `/vulnerabilities/<slug>/` | `vuln_detail` | Single vulnerability detail |
| `/system/<slug>/` | `system_detail` | All vulnerabilities for a system |
| `/actor/<slug>/` | `actor_detail` | All vulnerabilities by a threat actor |
| `/severity/<level>/` | `by_severity` | Filter by critical/high/medium/low |
| `/status/open/` | `open_vulns` | All open vulnerabilities |
| `/assets/` | `asset_list` | Registered web assets |
| `/assets/add/` | `asset_create` | Register a new web asset |
| `/assets/<id>/assess/` | `start_assessment` | Trigger a security assessment |
| `/assessments/` | `assessment_list` | All assessment runs |
| `/assessments/<id>/` | `assessment_detail` | Assessment results and findings |

---

## Data Models

### `AffectedSystem`
A system (e.g. web server, database) that vulnerabilities are attributed to.

### `ThreatActor`
A named threat actor with origin and description, optionally linked to vulnerabilities.

### `Vulnerability`
Core CVE record with severity (`C/H/M/L`), status (`O/IP/P`), foreign keys to `AffectedSystem` and `ThreatActor`.

### `WebAsset`
A registered HTTP/HTTPS target. Must have `is_authorized=True` before an assessment can be started.

### `AssessmentRun`
Tracks the lifecycle of a security assessment (`PENDING → RUNNING → COMPLETED/FAILED`).

### `AssessmentFinding`
An individual security observation generated by an assessment (e.g. missing `Content-Security-Policy` header).

---

## Security Checks Performed

Automated assessments inspect the HTTP response for:

**Security Headers**
| Header | Severity if missing |
|---|---|
| `Content-Security-Policy` | Medium |
| `Strict-Transport-Security` | Low (HTTPS only) |
| `X-Content-Type-Options` | Low |
| `Referrer-Policy` | Info |
| `Permissions-Policy` | Info |

**Cookie Attributes** (per `Set-Cookie` header)
| Missing attribute | Severity |
|---|---|
| `Secure` | Low |
| `HttpOnly` | Low |
| `SameSite` | Info |

---

## Running Tests

```bash
cd vulntracker

# Using pytest (recommended)
pytest

# Using Django's test runner
python manage.py test vulnerabilities
```

Test coverage includes assessment workflow states, finding persistence, transport failure handling, security header detection, and cookie attribute inspection.

---

## Production Checklist

- [ ] Set `DJANGO_SECRET_KEY` to a strong random value
- [ ] Set `DJANGO_DEBUG=False`
- [ ] Configure `DJANGO_ALLOWED_HOSTS` to your domain
- [ ] Run `python manage.py collectstatic`
- [ ] Serve behind HTTPS (Django auto-enables `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, and `CSRF_COOKIE_SECURE` when `DEBUG=False`)
- [ ] Use PostgreSQL or another production-grade database instead of SQLite
- [ ] Only register web assets you are **explicitly authorized** to assess

---

## License

This project is for educational and authorized-use purposes only. Do not run assessments against targets you do not own or have written permission to test.
