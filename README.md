# Pintheon - Decentralized File and Token Management

Pintheon is a decentralized file and token management application that integrates with Stellar blockchain and IPFS for secure, distributed file storage and tokenization.

## Architecture

Pintheon runs in an Ubuntu 24.04 Apptainer container with persistent storage via bind mounts:

- **Container OS**: Ubuntu 24.04
- **Container Data Path**: `/home/pintheon/data`
- **Host Bind Mounts**: Configurable per platform (see HOST_CONFIGURATION.md)

## Features

- **Decentralized File Storage**: IPFS integration for distributed file storage
- **Stellar Blockchain Integration**: Token creation and management on Stellar network
- **Encrypted Database**: Secure storage of application data
- **Apptainer Compatibility**: Containerized deployment with persistent storage
- **Cross-Platform Host Support**: Linux, macOS, Windows (WSL2)

## Storage Architecture

Pintheon uses a configurable data storage architecture designed for Apptainer containerization:

### Environment Variables

- `PINTHEON_DATA_DIR`: Base directory for persistent data
- `PINTHEON_IPFS_PATH`: IPFS repository location (default: `${PINTHEON_DATA_DIR}/ipfs`)
- `PINTHEON_DB_PATH`: Database storage location (default: `${PINTHEON_DATA_DIR}/db`)

### Default Directory Locations

**Development Environment** (no environment variables set):
- **Linux**: `~/.local/share/PINTHEON/`
- **macOS**: `~/Library/Application Support/PINTHEON/`
- **Windows**: `%LOCALAPPDATA%\PINTHEON\`

**Container Environment** (Apptainer/Docker):
- **Container**: `/home/pintheon/data/`

### Directory Structure

```
PINTHEON_DATA_DIR/
├── ipfs/                     # IPFS repository
│   ├── config               # IPFS configuration
│   ├── swarm.key            # Private swarm key
│   └── datastore/           # IPFS data storage
├── db/                      # Database files
│   └── enc_db.json         # Encrypted database
└── ...
```

## Quick Start

### Prerequisites

- Apptainer installed on host system
- Pintheon container image (`pintheon.sif`)

### Host Platform Setup

**Linux**:
```bash
sudo mkdir -p /opt/pintheon/data
sudo chown $USER:$USER /opt/pintheon/data
apptainer run --bind /opt/pintheon/data:/home/pintheon/data pintheon.sif
```

**macOS**:
```bash
mkdir -p ~/pintheon/data
apptainer run --bind ~/pintheon/data:/home/pintheon/data pintheon.sif
```

**Windows/WSL2**:
```bash
mkdir -p /mnt/c/pintheon/data
apptainer run --bind /mnt/c/pintheon/data:/home/pintheon/data pintheon.sif
```

### Development Environment

For development on a Linux VM:

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start Application** (uses platformdirs defaults)
   ```bash
   python3 pintheon.py
   ```

3. **Or set custom environment variables**
   ```bash
   export PINTHEON_DATA_DIR=/home/test
   export PINTHEON_IPFS_PATH=/home/test/.ipfs
   export PINTHEON_DB_PATH=/home/test/db
   python3 pintheon.py
   ```

4. **Install IPFS** (if needed)
   ```bash
   ./install_kubo.sh
   ```

## Host Configuration

For detailed host platform configuration, see [HOST_CONFIGURATION.md](HOST_CONFIGURATION.md).

## Migration from Old Structure

If migrating from the previous hardcoded paths:

```bash
./migrate_data.sh
```

## Configuration

See `CONFIGURATION.md` for detailed configuration options and troubleshooting.

### Localhost Route Restrictions

Pintheon supports restricting administrative routes to localhost-only access while keeping public routes accessible through tunnels. See `LOCALHOST_RESTRICTIONS.md` for detailed information.

## Security

- Database encryption using master key
- IPFS private network with swarm key
- Configurable directory permissions
- Environment-based configuration
- Localhost route restrictions for administrative access

## Development

- **Database**: TinyDB with encrypted JSON storage
- **Blockchain**: Stellar SDK with Soroban contracts
- **IPFS**: Kubo daemon with custom configuration
- **Web Framework**: Flask with CORS support

## License

[Add your license information here]
