#!/bin/bash
DIR="/home/.local/share/xelis-blockchain"

PROFILE=$(basename $SHELL)rc

echo "export PATH=\"\$PATH:$DIR\"" >> ~/.$PROFILE
echo "Path should've been updated to include $DIR
echo "Installing Rust:"
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
sudo apt install cargo -y
git clone https://github.com/xelis-project/xelis-blockchain
source ~/.profile
sudo chown -R test /home/test/xelis-blockchain/
cd xelis-blockchain
echo "Building Xelis:"
cargo build --release
mkdir -p /home/.local/share/xelis-blockchain

mv /home/test/xelis-blockchain/target/release/* /home/.local/share/xelis-blockchain/
echo "export xelis to path:"
source ~/.bashrc