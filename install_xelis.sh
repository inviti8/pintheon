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
sudo mv /home/test/xelis-blockchain/target/release/xelis_wallet /usr/local/bin
sudo mv /home/test/xelis-blockchain/target/release/xelis_daemon /usr/local/bin
export PATH="/home/test/xelis-blockchain/xelis_wallet:$PATH"
echo "Xelis is installed."