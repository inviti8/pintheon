# Host Configuration for Pintheon Apptainer

This guide explains how to configure Pintheon Apptainer containers on different host platforms.

## Container Architecture

- **Container OS**: Ubuntu 24.04
- **Container Data Path**: `/home/pintheon/data`
- **Apptainer Version**: Latest stable

## Host Platform Configuration

### Linux Host

**Recommended Host Path**: `/opt/pintheon/data`

```bash
# Create host directory
sudo mkdir -p /opt/pintheon/data
sudo chown $USER:$USER /opt/pintheon/data

# Run container with bind mount
apptainer run --bind /opt/pintheon/data:/home/pintheon/data pintheon.sif
```

**Alternative Paths**:
- `/var/lib/pintheon/data` (system-wide)
- `~/pintheon/data` (user-specific)

### macOS Host

**Recommended Host Path**: `~/pintheon/data`

```bash
# Create host directory
mkdir -p ~/pintheon/data

# Run container with bind mount
apptainer run --bind ~/pintheon/data:/home/pintheon/data pintheon.sif
```

**Alternative Paths**:
- `/opt/pintheon/data` (requires sudo)
- `/Users/username/pintheon/data` (explicit user path)

### Windows Host (WSL2)

**Recommended Host Path**: `/mnt/c/pintheon/data`

```bash
# Create host directory (accessible from Windows)
mkdir -p /mnt/c/pintheon/data

# Run container with bind mount
apptainer run --bind /mnt/c/pintheon/data:/home/pintheon/data pintheon.sif
```

**Alternative Paths**:
- `/home/username/pintheon/data` (WSL-only)
- `/mnt/d/pintheon/data` (if using D: drive)

## Environment Variables

You can override the default container paths if needed:

```bash
# Custom container paths
export PINTHEON_DATA_DIR=/custom/container/path
export PINTHEON_IPFS_PATH=/custom/container/path/ipfs
export PINTHEON_DB_PATH=/custom/container/path/db

# Run with custom paths
apptainer run --bind /host/path:/custom/container/path pintheon.sif
```

## Directory Structure

The container expects this structure in the bind-mounted directory:

```
/home/pintheon/data/          # Container path (bind mounted)
├── ipfs/                     # IPFS repository
│   ├── config               # IPFS configuration
│   ├── swarm.key            # Private swarm key
│   └── datastore/           # IPFS data storage
├── db/                      # Database files
│   └── enc_db.json         # Encrypted database
└── ...
```

## Security Considerations

### File Permissions

**Linux/macOS**:
```bash
# Set appropriate permissions
chmod 700 /host/path/to/data
chown $USER:$USER /host/path/to/data
```

**Windows/WSL**:
```bash
# WSL handles permissions automatically
# Ensure Windows Defender doesn't block the directory
```

### SELinux (Linux)

If using SELinux, you may need to set the appropriate context:

```bash
# Set SELinux context for bind mount
sudo semanage fcontext -a -t container_file_t "/opt/pintheon/data(/.*)?"
sudo restorecon -R /opt/pintheon/data
```

## Troubleshooting

### Permission Denied

```bash
# Check host directory permissions
ls -la /host/path/to/data

# Fix permissions
chmod 755 /host/path/to/data
chown $USER:$USER /host/path/to/data
```

### Container Can't Write to Bind Mount

```bash
# Check if directory exists and is writable
mkdir -p /host/path/to/data
chmod 755 /host/path/to/data
```

### IPFS Repository Issues

```bash
# Ensure IPFS directory exists
mkdir -p /host/path/to/data/ipfs

# Check IPFS configuration
ls -la /host/path/to/data/ipfs/
```

## Example Deployment Scripts

### Linux Production

```bash
#!/bin/bash
# deploy_pintheon.sh

HOST_DATA_DIR="/opt/pintheon/data"
CONTAINER_IMAGE="pintheon.sif"

# Create host directory
sudo mkdir -p $HOST_DATA_DIR
sudo chown $USER:$USER $HOST_DATA_DIR
chmod 755 $HOST_DATA_DIR

# Run container
apptainer run --bind $HOST_DATA_DIR:/home/pintheon/data $CONTAINER_IMAGE
```

### macOS Development

```bash
#!/bin/bash
# deploy_pintheon_macos.sh

HOST_DATA_DIR="$HOME/pintheon/data"
CONTAINER_IMAGE="pintheon.sif"

# Create host directory
mkdir -p $HOST_DATA_DIR

# Run container
apptainer run --bind $HOST_DATA_DIR:/home/pintheon/data $CONTAINER_IMAGE
```

### Windows/WSL

```bash
#!/bin/bash
# deploy_pintheon_windows.sh

HOST_DATA_DIR="/mnt/c/pintheon/data"
CONTAINER_IMAGE="pintheon.sif"

# Create host directory
mkdir -p $HOST_DATA_DIR

# Run container
apptainer run --bind $HOST_DATA_DIR:/home/pintheon/data $CONTAINER_IMAGE
``` 