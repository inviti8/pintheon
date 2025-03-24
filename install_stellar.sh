#!/bin/bash

# Make sure Cargo is installed and needed as a dependency to create the WASM lib
if command -v cargo &> /dev/null; then
  echo "Cargo is installed."
else 
  echo "Installing Cargo..."

  # Download & run rustup installer
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y

  # Source the Cargo env
  sudo apt install cargo -y

  echo "Cargo installed successfully."
fi

cargo install --locked stellar-cli@22.6.0 --features opt
source <(stellar completion --shell bash)
echo "source <(stellar completion --shell bash)" >> ~/.bashrc