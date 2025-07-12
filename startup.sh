#!/bin/bash

# Pintheon Startup Script for Apptainer Compatibility
# This script ensures the data directory structure exists and sets proper permissions

echo "Starting Pintheon with Apptainer-compatible data structure..."

# Set default environment variables if not provided
export PINTHEON_DATA_DIR=${PINTHEON_DATA_DIR:-/home/pintheon/data}
export PINTHEON_IPFS_PATH=${PINTHEON_IPFS_PATH:-$PINTHEON_DATA_DIR/ipfs}
export PINTHEON_DB_PATH=${PINTHEON_DB_PATH:-$PINTHEON_DATA_DIR/db}

echo "Using data directory: $PINTHEON_DATA_DIR"
echo "Using IPFS path: $PINTHEON_IPFS_PATH"
echo "Using DB path: $PINTHEON_DB_PATH"

# Create directory structure
echo "Creating directory structure..."
mkdir -p "$PINTHEON_DATA_DIR"
mkdir -p "$PINTHEON_IPFS_PATH"
mkdir -p "$PINTHEON_DB_PATH"

# Set permissions (adjust as needed for your security requirements)
echo "Setting permissions..."
chmod 755 "$PINTHEON_DATA_DIR"
chmod 755 "$PINTHEON_IPFS_PATH"
chmod 755 "$PINTHEON_DB_PATH"

# If running as root in container, ensure proper ownership
if [ "$(id -u)" = "0" ]; then
    echo "Running as root, setting ownership..."
    chown -R root:root "$PINTHEON_DATA_DIR"
fi

# Check if IPFS is already initialized
if [ ! -f "$PINTHEON_IPFS_PATH/config" ]; then
    echo "IPFS not initialized, will need to run IPFS setup..."
    echo "Please run the IPFS installation script if this is a fresh deployment."
else
    echo "IPFS repository found at $PINTHEON_IPFS_PATH"
fi

# Check if database exists
if [ -f "$PINTHEON_DB_PATH/enc_db.json" ]; then
    echo "Database found at $PINTHEON_DB_PATH/enc_db.json"
else
    echo "Database will be created at $PINTHEON_DB_PATH/enc_db.json on first run"
fi

echo "Pintheon startup preparation complete!"
echo "Starting Flask application..."

# Start the Flask application
exec python3 pintheon.py 