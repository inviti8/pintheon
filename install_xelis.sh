#!/bin/bash
echo "Installing Rust:"
echo "1\n y\n" | curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install cargo -y
git clone https://github.com/xelis-project/xelis-blockchain
source ~/.profile
sudo chown -R test /home/test/xelis-blockchain/
cd xelis-blockchain
echo "Building Xelis:"
cargo build --release
mkdir -p /home/.local/share/xelis-blockchain

mv /home/test/xelis-blockchain/target/release/* /home/.local/share/xelis-blockchain/
export PATH="/home/.local/share/xelis-blockchain/:$PATH"
echo "Xelis is installed."