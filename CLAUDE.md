# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AI Network Guardian** is a Flask web application providing a unified dashboard for network diagnosis and security analysis. It uses Google Gemini 2.0 Flash API for AI-powered diagnoses with a deterministic rule-based fallback engine.

## Commands

```bash
# Setup
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Run (port 5001)
python app.py

# Enable Gemini AI mode
set GEMINI_API_KEY=your-key-here  # Windows
python app.py
```

No test suite or linter is configured.

## Architecture

### Three Independent Diagnostic Modules

Each module operates at a specific TCP/IP layer and produces `Diagnosis` dataclass instances:

| Module | File | Layer | Purpose |
|--------|------|-------|---------|
| Network Detective | `network/detective.py` | L1/L2 (ARP, MAC) | Discover local network devices |
| Security Hunter | `network/security.py` | L7 (SSL/TLS, WHOIS) | Evaluate URL/domain security risk |
| Performance Monitor | `network/performance.py` | L3/L4 (ICMP, TCP/UDP) | Diagnose latency, packet loss, jitter |

### AI Reasoning Engine (`ai/reasoning.py`)

- **Primary**: Google Gemini 2.0 Flash via plain HTTP REST (no SDK)
- **Fallback**: Deterministic rule-based engine activated when `GEMINI_API_KEY` is absent or API fails
- `Diagnosis` dataclass fields: `title`, `layer`, `confidence` (0.0–1.0), `severity` (info/low/medium/high/critical), `evidence`, `explanation`, `recommendation`

### Data Flow

```
POST /api/<module>/... → app.py → network/<module>.py (raw data)
                                → ai/reasoning.py (diagnoses)
                                → database.py (persisted)
                                → JSON response
```

### Database (`database.py`)

SQLite with WAL mode. Key methods: `save_scan()`, `get_history()`, `get_trend()`. Indexed on `(module, timestamp)`.

### API Routes

- `POST /api/detective/scan` — network scan
- `POST /api/security/analyze` — URL security analysis (body: `{"url": "..."}`)
- `POST /api/performance/diagnose` — performance diagnostics (body: `{"target": "8.8.8.8"}`)
- `GET /api/history/<module>` — scan history
- `GET /api/trend/<module>` — trend data
- `GET /api/status` — current AI reasoning mode

### Frontend

Vanilla JS/HTML/CSS dark-theme dashboard (`static/js/app.js`, `templates/index.html`). Tab-based module switching, diagnosis cards with severity/confidence badges, modal history viewer.
