# Pintheon Configuration for Apptainer

This document describes the configurable data storage architecture for Pintheon when running in Apptainer containers.

## Environment Variables

### Core Data Directory
- `PINTHEON_DATA_DIR`: Base directory for all persistent data (default: `/home/pintheon/data`)

### Subdirectories
- `PINTHEON_IPFS_PATH`: IPFS repository location (default: `${PINTHEON_DATA_DIR}/ipfs`)
- `PINTHEON_DB_PATH`: Database storage location (default: `${PINTHEON_DATA_DIR}/db`)

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
export PINTHEON_DATA_DIR=/home/test
export PINTHEON_IPFS_PATH=/home/test/.ipfs
export PINTHEON_DB_PATH=/home/test/db
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
2. Copy existing database: `cp enc_db.json /home/pintheon/data/db/`
3. Copy existing IPFS repo: `cp -r .ipfs /home/pintheon/data/ipfs`
4. Set environment variables
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