#!/bin/bash

# Make sure Cargo is installed and needed as a dependency to create the WASM lib
if command -v cargo &> /dev/null; then
  echo "Cargo is installed."
else 
  echo "Installing Cargo..."

  # Download & run rustup installer
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

  # Source the Cargo env
  source "$HOME/.cargo/env"

  echo "Cargo installed successfully."
fi
source ~/.bashrc
source ~/.profile
# Make sure wasm-pack is installed
cargo install wasm-pack

source ~/.bashrc
source ~/.profile

wasm-pack --version

# Create WASM lib for javascript browser
cd /home/test/axiel/xelis-paper-wallet
wasm-pack build --no-typescript --target no-modules --release

# Copy files in static folder
cp pkg/xelis_paper_wallet_bg.wasm ../axiel/static/
cp pkg/xelis_paper_wallet.js ../axiel/static/