#!/bin/bash

# Pintheon Data Migration Script
# This script helps migrate from the old hardcoded paths to the new configurable structure

echo "Pintheon Data Migration Script"
echo "=============================="

# Set default environment variables
export PINTHEON_DATA_DIR=${PINTHEON_DATA_DIR:-/home/pintheon/data}
export PINTHEON_IPFS_PATH=${PINTHEON_IPFS_PATH:-$PINTHEON_DATA_DIR/ipfs}
export PINTHEON_DB_PATH=${PINTHEON_DB_PATH:-$PINTHEON_DATA_DIR/db}

# Old paths (hardcoded)
OLD_SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
OLD_DB_PATH="$OLD_SCRIPT_DIR/enc_db.json"
OLD_IPFS_PATH="/home/pintheon/data/ipfs"

echo "New data directory: $PINTHEON_DATA_DIR"
echo "New IPFS path: $PINTHEON_IPFS_PATH"
echo "New DB path: $PINTHEON_DB_PATH"
echo "Old DB path: $OLD_DB_PATH"
echo "Old IPFS path: $OLD_IPFS_PATH"
echo ""

# Create new directory structure
echo "Creating new directory structure..."
mkdir -p "$PINTHEON_DATA_DIR"
mkdir -p "$PINTHEON_IPFS_PATH"
mkdir -p "$PINTHEON_DB_PATH"

# Migrate database
if [ -f "$OLD_DB_PATH" ]; then
    echo "Found old database at $OLD_DB_PATH"
    echo "Migrating database to $PINTHEON_DB_PATH/enc_db.json..."
    cp "$OLD_DB_PATH" "$PINTHEON_DB_PATH/enc_db.json"
    echo "Database migration complete!"
else
    echo "No old database found at $OLD_DB_PATH"
fi

# Migrate IPFS repository
if [ -d "$OLD_IPFS_PATH" ]; then
    echo "Found old IPFS repository at $OLD_IPFS_PATH"
    echo "Migrating IPFS repository to $PINTHEON_IPFS_PATH..."
    cp -r "$OLD_IPFS_PATH"/* "$PINTHEON_IPFS_PATH/"
    echo "IPFS repository migration complete!"
else
    echo "No old IPFS repository found at $OLD_IPFS_PATH"
fi

# Set permissions
echo "Setting permissions..."
chmod 755 "$PINTHEON_DATA_DIR"
chmod 755 "$PINTHEON_IPFS_PATH"
chmod 755 "$PINTHEON_DB_PATH"

# If running as root, set ownership
if [ "$(id -u)" = "0" ]; then
    echo "Setting ownership for root user..."
    chown -R root:root "$PINTHEON_DATA_DIR"
fi

echo ""
echo "Migration complete!"
echo ""
echo "Next steps:"
echo "1. Set environment variables:"
echo "   export PINTHEON_DATA_DIR=$PINTHEON_DATA_DIR"
echo "   export PINTHEON_IPFS_PATH=$PINTHEON_IPFS_PATH"
echo "   export PINTHEON_DB_PATH=$PINTHEON_DB_PATH"
echo ""
echo "2. Restart the Pintheon application"
echo ""
echo "3. For Apptainer, bind mount the data directory:"
echo "   apptainer run --bind /host/path/to/data:$PINTHEON_DATA_DIR pintheon.sif" 