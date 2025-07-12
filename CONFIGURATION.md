# Pintheon Configuration for Apptainer

This document describes the configurable data storage architecture for Pintheon when running in Apptainer containers.

## Environment Variables

### Core Data Directory
- `PINTHEON_DATA_DIR`: Base directory for all persistent data

### Subdirectories
- `PINTHEON_IPFS_PATH`: IPFS repository location (default: `${PINTHEON_DATA_DIR}/ipfs`)
- `PINTHEON_DB_PATH`: Database storage location (default: `${PINTHEON_DATA_DIR}/db`)

## Default Directory Locations

### Development Environment (No Environment Variables Set)
When no environment variables are set, Pintheon uses `platformdirs` to determine the data location:

**Linux Development**:
```
~/.local/share/PINTHEON/
├── ipfs/                     # IPFS repository
├── db/                       # Database files
│   └── enc_db.json          # Encrypted database
└── ...
```

**macOS Development**:
```
~/Library/Application Support/PINTHEON/
```

**Windows Development**:
```
%LOCALAPPDATA%\PINTHEON\
```

### Container Environment (Apptainer/Docker)
When running in a container environment, Pintheon uses:

```
/home/pintheon/data/
├── ipfs/                     # IPFS repository
├── db/                       # Database files
│   └── enc_db.json          # Encrypted database
└── ...
```

### Custom Environment Variables
You can override the default behavior by setting environment variables:

```bash
export PINTHEON_DATA_DIR=/custom/path
export PINTHEON_IPFS_PATH=/custom/path/ipfs
export PINTHEON_DB_PATH=/custom/path/db
```

## Directory Structure

```
PINTHEON_DATA_DIR/
├── ipfs/                    # IPFS repository
│   ├── config              # IPFS configuration
│   ├── swarm.key           # Private swarm key
│   ├── datastore/          # IPFS data storage
│   └── ...
├── db/                     # Database files
│   └── enc_db.json        # Encrypted database
└── ...
```

## Usage Examples

### Development Environment (Manual VM Installation)
```bash
# No environment variables needed - uses platformdirs defaults
python3 pintheon.py
```

### Production Apptainer
```bash
export PINTHEON_DATA_DIR=/home/pintheon/data
export PINTHEON_IPFS_PATH=/home/pintheon/data/ipfs
export PINTHEON_DB_PATH=/home/pintheon/data/db
```

### Custom Host Path
```bash
export PINTHEON_DATA_DIR=/opt/pintheon/data
export PINTHEON_IPFS_PATH=/opt/pintheon/data/ipfs
export PINTHEON_DB_PATH=/opt/pintheon/data/db
```

## Script Usage

### Development Scripts (Manual VM Installation)
- `install_kubo.sh` - Uses `/home/test/.ipfs` for development
- `init.sh` - Development initialization
- `setup.sh` - Development setup

### Apptainer Scripts (Containerized Deployment)
- `install_kubo_apptainer.sh` - Uses `/home/pintheon/data/ipfs` for production
- `init_apptainer.sh` - Apptainer initialization
- `setup_apptainer.sh` - Apptainer setup

## Apptainer Bind Mounts

To persist data across container restarts, bind mount the data directory:

```bash
apptainer run --bind /host/path/to/data:/home/pintheon/data pintheon.sif
```

## Migration from Old Structure

The application automatically creates the new directory structure. If migrating from the old hardcoded paths:

1. Stop the application
2. Copy existing database: `cp enc_db.json /path/to/new/data/db/`
3. Copy existing IPFS repo: `cp -r .ipfs /path/to/new/data/ipfs`
4. Set environment variables (if needed)
5. Restart the application

## Security Considerations

- Database files are encrypted using the master key
- IPFS swarm key provides private network isolation
- Directory permissions should be set appropriately for your deployment
- Consider using separate volumes for different data types in production

## Troubleshooting

### Database Not Found
- Check `PINTHEON_DB_PATH` environment variable
- Ensure directory exists and is writable
- Verify database file permissions

### IPFS Connection Issues
- Check `PINTHEON_IPFS_PATH` environment variable
- Ensure IPFS daemon is running
- Verify IPFS repository is initialized

### Permission Denied
- Check directory ownership and permissions
- Ensure user has write access to data directories
- Verify Apptainer bind mount permissions

### Finding Your Data Directory
To find where Pintheon is storing data:

```bash
# Check environment variables
echo $PINTHEON_DATA_DIR

# Or run this Python code
python3 -c "import pintheon; print('Data directory:', pintheon.PINTHEON_DATA_DIR)"
``` 