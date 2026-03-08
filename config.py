"""
Pintheon Configuration

Single source of truth for all environment-dependent settings.
Reads from: CLI flags → environment variables → .env file → defaults.

Usage:
    uv run python pintheon.py --debug              # testnet, debug logging, port 5000
    uv run python pintheon.py --debug --fake-ipfs  # same + fake IPFS data
    uv run python pintheon.py                      # production defaults from .env
"""

import logging
import os
import sys

# --- CLI flags (parsed before anything else, stripped from sys.argv) ---
if '--fake-ipfs' in sys.argv:
    os.environ['PINTHEON_FAKE_IPFS'] = 'true'
    sys.argv.remove('--fake-ipfs')

if '--debug' in sys.argv:
    os.environ['PINTHEON_DEBUG'] = 'true'
    os.environ.setdefault('PINTHEON_NETWORK', 'testnet')
    sys.argv.remove('--debug')

# Load .env file if present (does not override existing env vars)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- Core flags ---
DEBUG = os.getenv('PINTHEON_DEBUG', 'false').lower() == 'true'
FAKE_IPFS = os.getenv('PINTHEON_FAKE_IPFS', 'false').lower() == 'true'
NETWORK = os.getenv('PINTHEON_NETWORK', 'testnet')

IN_CONTAINER = os.path.exists('/.dockerenv') or bool(os.environ.get('APPTAINER_CONTAINER'))


# --- Data directory resolution ---
def _resolve_data_dir():
    """Resolve the data directory: env var > debug path > container path > platformdirs."""
    env = os.environ.get('PINTHEON_DATA_DIR')
    if env:
        return env
    if DEBUG:
        return os.path.expanduser('~/.local/share/PINTHEON')
    if IN_CONTAINER:
        container_path = '/home/pintheon/data'
        try:
            os.makedirs(container_path, exist_ok=True)
            return container_path
        except (OSError, PermissionError):
            pass
    try:
        from platformdirs import PlatformDirs
        return PlatformDirs('PINTHEON', ensure_exists=True).user_data_dir
    except ImportError:
        fallback = os.path.expanduser('~/.local/share/PINTHEON')
        os.makedirs(fallback, exist_ok=True)
        return fallback


DATA_DIR = _resolve_data_dir()
IPFS_PATH = os.environ.get('PINTHEON_IPFS_PATH', os.path.join(DATA_DIR, 'ipfs'))
DB_PATH = os.environ.get('PINTHEON_DB_PATH', os.path.join(DATA_DIR, 'db'))
CUSTOM_HOMEPAGE_PATH = os.path.join(DATA_DIR, 'custom_homepage')

IPFS_DAEMON = os.getenv('PINTHEON_IPFS_DAEMON', 'http://127.0.0.1:5001')
PORT = int(os.getenv('PINTHEON_PORT', '5000' if DEBUG else '9999'))
HOST = os.getenv('PINTHEON_HOST', '127.0.0.1' if DEBUG else '0.0.0.0')


# --- Ensure directories exist ---
for _d in [DATA_DIR, IPFS_PATH, DB_PATH, CUSTOM_HOMEPAGE_PATH]:
    try:
        os.makedirs(_d, exist_ok=True)
    except (OSError, PermissionError) as _e:
        print(f"Warning: Could not create directory {_d}: {_e}")


# --- Startup log ---
if DEBUG:
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger(__name__).warning(
        'DEBUG MODE — network=%s, fake_ipfs=%s, port=%d, data=%s',
        NETWORK, FAKE_IPFS, PORT, DATA_DIR,
    )
