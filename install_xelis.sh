#!/bin/bash
echo "Installing Rust:"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/xelis-project/xelis-blockchain
source ~/.profile
cd xelis-blockchain
cargo build --release