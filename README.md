# Paranoid Scanner (parascan)

A modular web application penetration testing tool for REST and GraphQL APIs.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Quick Start

```bash
# install
git clone https://github.com/parascan/parascan.git
cd parascan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# scan a target
parascan scan https://example.com

# view results
parascan dashboard
```

## Installation

**Prerequisites:** Python 3.11 or later.

```bash
git clone https://github.com/parascan/parascan.git
cd parascan

# create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate

# install in development mode
pip install -e .
```

Or install dependencies directly:

```bash
pip install -r requirements.txt
```

Verify installation:

```bash
parascan version
```

## Usage

### Basic Scanning

Point parascan at a URL and it handles everything — crawls the target, discovers endpoints, runs all scanners, and saves results:

```bash
parascan scan https://example.com
```

Import an OpenAPI/Swagger spec for better endpoint coverage:

```bash
parascan scan https://api.example.com --openapi swagger.yaml
```

### Authenticated Scanning

Most real apps require auth. Pass credentials as CLI flags:

```bash
# bearer token (JWT, OAuth, etc.)
parascan scan https://example.com --bearer "eyJhbGciOiJIUzI1NiIs..."

# cookies
parascan scan https://example.com --cookie "session=abc123; csrf=xyz"

# API key (format: "Header-Name: value")
parascan scan https://example.com --api-key "X-API-Key: your-key-here"

# basic auth
parascan scan https://example.com --basic-auth "admin:password"
```

### Module Selection

Run specific scanners or exclude ones you don't need:

```bash
# only run SQL injection and XSS scanners
parascan scan https://example.com --modules sqli,xss

# run everything except IDOR and CSRF
parascan scan https://example.com --exclude-modules idor,csrf

# only GraphQL scanners
parascan scan https://example.com --modules graphql-introspection,graphql-injection,graphql-batch
```

List all available modules:

```bash
parascan modules
```

### Tuning

Control scan speed and behavior:

```bash
# slow down for sensitive targets
parascan scan https://example.com --rate-limit 5 --concurrency 5

# speed up for local/staging environments
parascan scan https://staging.local --rate-limit 50 --concurrency 30

# route through Burp Suite or OWASP ZAP
parascan scan https://example.com --proxy http://127.0.0.1:8080
```

### CI/CD Integration

Run parascan in pipelines. Returns exit code 1 if critical or high severity findings are detected:

```bash
parascan scan https://example.com --ci

# exit code 0 = no critical/high findings
# exit code 1 = critical/high findings detected
# stdout = JSON report
```

### Resume and Dashboard

```bash
# resume an interrupted scan
parascan scan --resume

# launch the web dashboard
parascan dashboard

# dashboard on a custom port
parascan dashboard --port 9000
```

## Configuration File

For complex setups, use a YAML config file instead of CLI flags. See [`config.example.yaml`](config.example.yaml) for the full format.

```bash
parascan scan --config target.yaml
```

CLI flags override config file values, so you can use a base config and tweak per-run:

```bash
parascan scan --config target.yaml --modules sqli,xss --rate-limit 5
```

### Config File Format

```yaml
target:
  url: https://example.com
  openapi: ./swagger.yaml

auth:
  bearer: "eyJhbG..."
  # or: cookie, api_key, basic

scope:
  allowed_domains:
    - example.com
  excluded_paths:
    - /logout
    - /admin/delete

scan:
  modules: []          # empty = all
  exclude_modules: []
  concurrency: 10
  rate_limit: 10

proxy:
  url: http://127.0.0.1:8080
```

## Vulnerability Modules

| Module | What it tests | Severity range |
|--------|--------------|----------------|
| `sqli` | SQL injection (error-based, boolean-blind, time-blind) | High |
| `xss` | Reflected cross-site scripting | High - Medium |
| `ssrf` | Server-side request forgery | Critical - Medium |
| `cmdi` | OS command injection | Critical |
| `idor` | Insecure direct object references | High |
| `headers` | Missing security headers, CORS misconfig | Medium - Info |
| `traversal` | Directory/path traversal | High |
| `csrf` | Missing CSRF tokens, SameSite cookie issues | Medium - Low |
| `jwt` | JWT alg:none bypass, weak secret brute-force | Critical |
| `xxe` | XML external entity injection | Critical |
| `redirect` | Open redirect | Medium |
| `graphql-introspection` | GraphQL introspection enabled | Medium |
| `graphql-injection` | GraphQL query injection | High - Medium |
| `graphql-batch` | GraphQL batch/nested query DoS | Medium - Low |

All modules run by default. Use `--modules` or `--exclude-modules` to customize.

## How It Works

1. **Legal disclaimer** — parascan requires you to confirm authorization before scanning
2. **Fingerprinting** — detects the target's tech stack, server software, and WAF
3. **Discovery** — crawls the target, imports OpenAPI specs, or uses your endpoint list
4. **Scanning** — runs selected vulnerability modules against each endpoint
5. **Reporting** — saves findings to SQLite, prints a summary, and serves results via the dashboard

parascan is a **detection tool**, not an exploitation framework. It identifies vulnerabilities and provides evidence but does not exploit them.

### Scan Data

All scan data is stored locally in `~/.parascan/parascan.db` (SQLite). No data is sent to external services.

## Database Configuration

parascan supports both **SQLite** (local, default) and **PostgreSQL** (centralized, production).

### Default: SQLite

By default, parascan uses SQLite at `~/.parascan/parascan.db`. This works great for:
- Local development
- Single-user scanning
- Laptop-based testing

### PostgreSQL for Centralized Deployments

To enable distributed scanning (multiple workers writing to one database) or deploy the dashboard to Vercel/similar platforms, use PostgreSQL:

**Option 1: Environment Variable**

```bash
export DATABASE_URL="postgresql://user:pass@db.example.com:5432/parascan"
parascan scan https://example.com  # writes to PostgreSQL
parascan dashboard                  # reads from PostgreSQL
```

**Option 2: CLI Parameter** (overrides env var)

```bash
parascan scan https://example.com --database-url "postgresql://..."
parascan dashboard --database-url "postgresql://..."
```

**Install PostgreSQL support:**

```bash
pip install -e ".[postgres]"
```

### Use Cases

**Local scanning (default):**
```bash
parascan scan https://example.com  # uses SQLite
```

**CI/CD + centralized dashboard:**
```bash
# .env or CI secrets
DATABASE_URL=postgresql://user:pass@db.example.com:5432/parascan

# scan writes to PostgreSQL
parascan scan https://api.example.com

# deploy dashboard to Vercel (reads from PostgreSQL)
vercel deploy
```

**Multiple scan workers:**
```bash
# laptop 1
parascan scan https://api.prod.com --database-url "postgresql://..."

# laptop 2
parascan scan https://api.staging.com --database-url "postgresql://..."

# both write to same PostgreSQL instance
# dashboard shows all scans in one place
```

### Recommended PostgreSQL Providers

- **Neon** (free tier, serverless, auto-scaling)
- **Supabase** (free tier, includes UI)
- **Vercel Postgres** (if deploying dashboard to Vercel)
- **Railway** (cheap, easy setup)
- **AWS RDS / DigitalOcean Managed DB** (production-grade)

## Dashboard

Launch the web dashboard to browse scan results:

```bash
parascan dashboard
```

The dashboard shows:
- Scan history with status and endpoint counts
- Findings grouped by severity with request/response evidence
- JSON export and standalone HTML report per scan
- Served locally on `http://127.0.0.1:8000` by default

## Legal Disclaimer

parascan is designed for **authorized penetration testing and security research only**.

- You **must** have written permission from the system owner before running any scans.
- Unauthorized access to computer systems is illegal in most jurisdictions.
- The authors accept no liability for misuse of this tool.

parascan will prompt you to confirm authorization before each new target.

## Contributing

### Adding a Custom Scanner Module

1. Create a new file in `src/parascan/scanners/`
2. Inherit from `BaseScanner` and implement the `scan()` method:

```python
from parascan.scanners.base import BaseScanner, ScanResult

class MyScanner(BaseScanner):
    module_name = "my-scanner"
    description = "Description of what it tests"

    async def scan(self, client, endpoint):
        results = []
        # your scanning logic here
        return results
```

3. Register it in `src/parascan/core/engine.py` in the `_get_all_scanner_classes()` function
4. Add payload files in `src/parascan/payloads/` if needed

## License

MIT — see [LICENSE](LICENSE).
