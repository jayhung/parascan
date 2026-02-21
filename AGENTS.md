# parascan - AI Agent Guide

This file provides context for AI agents working with the parascan project.

## Project Overview

A modular Python penetration testing CLI application with a web dashboard, targeting web applications (REST + GraphQL APIs) with comprehensive vulnerability scanning, endpoint discovery, rate limiting, proxy support, and scope enforcement. Uses SQLite for local storage with a hosting-ready architecture.

## Tech Stack

- **CLI**: Typer (modern, type-hinted CLI framework)
- **HTTP engine**: httpx (async support, HTTP/2, proxy support)
- **Web dashboard**: FastAPI + Jinja2 templates
- **Database**: SQLite via aiosqlite + SQLAlchemy (async ORM)
- **Payload management**: YAML files per vulnerability type
- **Reporting**: JSON + HTML via Jinja2 templates
- **Config**: YAML target config files
- **Package management**: pyproject.toml (PEP 621)
- **License**: MIT

## Project Structure

```
src/
└── parascan/
    ├── __init__.py
    ├── cli.py                    # typer CLI entrypoint + legal disclaimer
    ├── core/
    │   ├── __init__.py
    │   ├── engine.py             # orchestrates scans, manages async HTTP sessions
    │   ├── auth.py               # auth manager (bearer, cookie, api key, basic)
    │   ├── config.py             # target config loading (YAML)
    │   ├── db.py                 # SQLAlchemy models + async SQLite session
    │   ├── reporter.py           # generates JSON + HTML reports from DB
    │   ├── rate_limiter.py       # configurable requests-per-second throttling
    │   ├── proxy.py              # proxy support (Burp, ZAP, custom)
    │   ├── scope.py              # scope enforcement (allowed domains/paths)
    │   ├── state.py              # scan state persistence and resume
    │   └── fingerprint.py        # target tech stack detection
    ├── discovery/
    │   ├── __init__.py
    │   ├── crawler.py            # basic web spider for endpoint discovery
    │   ├── openapi.py            # OpenAPI/Swagger spec parser
    │   ├── graphql_schema.py     # GraphQL introspection-based endpoint generation
    │   └── directory_brute.py    # directory/endpoint brute-forcing
    ├── scanners/
    │   ├── __init__.py
    │   ├── base.py               # base scanner class (interface)
    │   ├── sqli.py               # SQL injection
    │   ├── xss.py                # reflected XSS
    │   ├── ssrf.py               # SSRF detection
    │   ├── cmdi.py               # OS command injection
    │   ├── idor.py               # insecure direct object reference
    │   ├── headers.py            # security headers & CORS
    │   ├── directory_traversal.py # path traversal
    │   ├── csrf.py               # CSRF token checks
    │   ├── jwt.py                # JWT attacks
    │   ├── xxe.py                # XML external entity injection
    │   ├── open_redirect.py      # open redirect detection
    │   └── graphql/
    │       ├── __init__.py
    │       ├── introspection.py  # checks if introspection is enabled
    │       ├── injection.py      # GraphQL-specific injection
    │       └── batch.py          # batch query / nested query DoS
    ├── payloads/
    │   ├── sqli.yaml
    │   ├── xss.yaml
    │   ├── ssrf.yaml
    │   ├── cmdi.yaml
    │   ├── traversal.yaml
    │   ├── csrf.yaml
    │   ├── jwt.yaml
    │   ├── xxe.yaml
    │   └── redirect.yaml
    ├── wordlists/
    │   └── directories.txt
    └── web/
        ├── __init__.py
        ├── app.py                # FastAPI app
        └── templates/            # Jinja2 HTML templates

tests/
├── __init__.py
├── test_engine.py
└── test_scanners/
    └── __init__.py

configs/
├── config.example.yaml       # example target config (copy and rename per project)
└── specs/                    # openapi/swagger specs (tracked, safe to commit)
pyproject.toml                # dependencies, metadata, CLI entry point
requirements.txt              # auto-generated from pyproject.toml
README.md
LICENSE
```

## Coding Conventions

### Python
- use type hints for all function signatures
- prefer async/await for I/O operations
- use dataclasses or Pydantic models for structured data
- follow PEP 8 style guide

### Code Style
- comments: start lowercase unless multi-line paragraph
- prefer concise, readable code
- extract reusable logic to appropriate modules in `core/`

### Async Operations
- all HTTP requests use httpx async client
- scanner modules implement async `scan()` methods
- database operations use aiosqlite

### Database
- SQLAlchemy models in `core/db.py`
- use async sessions for all queries
- findings stored with full request/response evidence

### Scanner Development
- all scanners inherit from `BaseScanner`
- implement async `scan(client, endpoint)` method
- return list of `Finding` objects with severity, description, evidence
- payloads loaded from YAML files in `payloads/`

## Key Files

- `cli.py`: CLI entry point, command definitions, legal disclaimer
- `core/engine.py`: scan orchestration, async HTTP client management
- `core/db.py`: database schema and ORM models
- `core/auth.py`: authentication methods for authenticated scanning
- `scanners/base.py`: base scanner interface that all modules implement
- `web/app.py`: FastAPI dashboard application
- `pyproject.toml`: dependencies, metadata, CLI entry point configuration

## Development

**Package Manager**: Always use `pip` (standard Python)

```bash
# install in development mode
pip install -e .

# or install dependencies directly
pip install -r requirements.txt

# run the CLI
parascan --help
parascan scan https://example.com

# launch dashboard
parascan dashboard

# run tests
pytest
```

## Environment

- scan data stored in `~/.parascan/parascan.db`
- no external API keys required (unless using external SSRF canaries)
- dashboard runs on `http://127.0.0.1:8000` by default

## Common Tasks

- **Adding a scanner module**: create new file in `scanners/`, inherit from `BaseScanner`, implement `scan()` method, add payloads to `payloads/`
- **Adding auth methods**: update `core/auth.py` and CLI argument parser in `cli.py`
- **Modifying database schema**: update models in `core/db.py`, consider migration strategy
- **Adding CLI commands**: add new command functions in `cli.py` using Typer decorators
- **Updating dashboard**: modify FastAPI routes in `web/app.py` and templates in `web/templates/`

## Design Principles

1. **Zero-config by default**: `parascan scan <url>` should work with no flags
2. **Progressive complexity**: CLI flags for common options, YAML config for advanced setups
3. **Async-first**: all I/O operations are async for performance
4. **Modular scanners**: easy to add/remove vulnerability modules
5. **Evidence-based**: every finding includes request/response evidence
6. **Scope enforcement**: strict allow-list to prevent out-of-scope scanning
7. **Rate limiting**: built-in throttling to avoid crashes and WAF bans
