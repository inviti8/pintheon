#!/bin/bash

# Make sure Cargo is installed and needed as a dependency to create the WASM lib
if command -v cargo &> /dev/null; then
  echo "Cargo is installed."
else 
  echo "Installing Cargo..."

  # Download & run rustup installer
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

  # Source the Cargo env
  #source "$HOME/.cargo/env"
  sudo apt install cargo -y

  echo "Cargo installed successfully."
fi

sudo apt install rustup

# Make sure wasm-pack is installed
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
#cargo install wasm-pack

source ~/.bashrc

# Create WASM lib for javascript browser
cd xelis-paper-wallet
wasm-pack build --no-typescript --target no-modules --release

# Copy files in static folder
cp pkg/xelis_paper_wallet_bg.wasm ../axiel/static/
cp pkg/xelis_paper_wallet.js ../axiel/static/