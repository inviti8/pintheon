#!/bin/bash
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
export PATH="/home/.local/share/xelis-blockchain/:$PATH"
echo "Xelis is installed."
./home/test/axiel/update_path.sh
source ~/.bashrc