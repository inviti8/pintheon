# Developer Flow

Run the Pintheon gateway locally with testnet contracts and debug logging.

## Setup

```bash
# Install uv if you don't have it
pip install uv

# Create venv and install dependencies
uv venv
uv pip install -r requirements.txt

# Copy the env template (defaults work for local dev)
cp .env.example .env
```

## Quick Start

```bash
# Local dev — testnet, debug logging, Flask on :5000
uv run python pintheon.py --debug

# Local dev without Kubo (fake IPFS data)
uv run python pintheon.py --debug --fake-ipfs

# Production mode — reads .env, binds 0.0.0.0:9999
uv run python pintheon.py
```

## Flags

| Flag | What it does |
|------|--------------|
| `--debug` | Testnet network + contracts, Flask debug mode, binds `127.0.0.1:5000`, data stored in `~/.local/share/PINTHEON` |
| `--fake-ipfs` | Uses fake IPFS data (no running Kubo node required) |

Flags can be combined:

```bash
uv run python pintheon.py --debug --fake-ipfs
```

## Configuration

All settings are driven by `config.py`, which reads in this order:

1. CLI flags (`--debug`, `--fake-ipfs`)
2. Environment variables
3. `.env` file
4. Defaults

### Environment Variables

| Variable | Default (debug) | Default (prod) | Purpose |
|----------|-----------------|----------------|---------|
| `PINTHEON_DEBUG` | `true` | `false` | Master debug toggle |
| `PINTHEON_FAKE_IPFS` | — | `false` | Use fake IPFS data |
| `PINTHEON_NETWORK` | `testnet` | `testnet` | Stellar network (`testnet` or `mainnet`) |
| `PINTHEON_DATA_DIR` | `~/.local/share/PINTHEON` | platformdirs | Data directory root |
| `PINTHEON_DB_PATH` | `${DATA_DIR}/db` | `${DATA_DIR}/db` | TinyDB directory |
| `PINTHEON_IPFS_PATH` | `${DATA_DIR}/ipfs` | `${DATA_DIR}/ipfs` | IPFS repo path |
| `PINTHEON_IPFS_DAEMON` | `http://127.0.0.1:5001` | `http://127.0.0.1:5001` | Kubo RPC URL |
| `PINTHEON_PORT` | `5000` | `9999` | Flask listen port |
| `PINTHEON_HOST` | `127.0.0.1` | `0.0.0.0` | Flask bind address |

Override any setting inline:

```bash
PINTHEON_PORT=8080 uv run python pintheon.py --debug
PINTHEON_IPFS_DAEMON=http://192.168.1.50:5001 uv run python pintheon.py --debug
```

## Common Workflows

### Daily development (with Kubo running)

```bash
uv run python pintheon.py --debug
```

Requires a Kubo IPFS node running on `localhost:5001` (the Pintheon Docker container, or a local Kubo install).

### UI/frontend work (no IPFS needed)

```bash
uv run python pintheon.py --debug --fake-ipfs
```

The dashboard loads with fake IPFS stats and dummy files. Useful for working on templates, JS, or routes that don't touch IPFS.

### Testing against mainnet contracts

```bash
PINTHEON_NETWORK=mainnet uv run python pintheon.py --debug
```

Still runs locally with debug logging, but uses mainnet contract IDs and Stellar horizon.

## What Debug Mode Changes

- **Network:** Forces `testnet` (override with `PINTHEON_NETWORK=mainnet`)
- **Contracts:** Testnet contract IDs (XLM, Collective, Opus, Pin Service)
- **Server:** Flask dev server with hot reload on `127.0.0.1:5000`
- **Data directory:** `~/.local/share/PINTHEON` (instead of platformdirs or container path)
- **Logging:** Debug-level output from Flask, urllib3, transitions

## What Debug Mode Does NOT Change

- Flask app structure, routes, and decorators
- Authentication (macaroon tokens, access tokens, session management)
- TinyDB schema and file_book structure
- Stellar contract interactions (real testnet contracts)
- Frontend behavior (static JS/HTML/CSS)

## Production / Container

```bash
# Direct Flask (reads .env)
uv run python pintheon.py

# Gunicorn
uv run gunicorn --workers 1 --bind unix:pintheon.sock wsgi:app

# Container startup (startup.sh sets env vars, uses system Python)
exec python3 pintheon.py
```

Container environments are auto-detected (`/.dockerenv` or `APPTAINER_CONTAINER` env var). Data defaults to `/home/pintheon/data` inside containers.

## Project Structure

```
pintheon/
├── config.py                  # Configuration (CLI flags, env vars, defaults)
├── pintheon.py                # Flask app and routes
├── wsgi.py                    # Gunicorn entry point
├── pintheonMachine/
│   ├── __init__.py            # PintheonMachine class (state machine, IPFS, Stellar)
│   └── pinning_service_bindings.py
├── StellarTomlGenerator/      # Local package for stellar.toml generation
├── static/                    # Frontend assets (JS, CSS, images)
├── templates/                 # Jinja2 templates
├── components/                # HTML components
├── .env.example               # Environment variable template
├── .env                       # Local overrides (not committed)
├── requirements.txt           # Pinned dependencies
├── startup.sh                 # Container startup script
└── .venv/                     # Virtual environment (created by uv)
```
