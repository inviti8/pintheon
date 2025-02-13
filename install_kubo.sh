#!/bin/bash
echo "ipfs install"
# . "$HOME/.bash_profile"
echo 'sudo apt update'
sudo apt update -y

echo 'sudo apt upgrade'
sudo apt upgrade -y

script_dir=$(dirname "$0")

export SWARM_KEY=$(tr -dc a-f0-9 </dev/urandom | head -c 64; echo '')
echo "Created secret: $SWARM_KEY"

export LIBP2P_FORCE_PNET=1
ver="v0.31.0" 
echo 'wget https://dist.ipfs.tech/kubo/v0.31.0/kubo_v0.31.0_linux-amd64.tar.gz'
wget https://dist.ipfs.tech/kubo/v0.31.0/kubo_v0.31.0_linux-amd64.tar.gz

echo 'tar -xvzf kubo_v0.31.0_linux-amd64.tar.gz'
tar -xvzf kubo_v0.31.0_linux-amd64.tar.gz

echo './kubo/install.sh'
./kubo/install.sh

#sudo bash $HOME/kubo/install.sh
ipfs --version

#CREATE THE SWARM KEY
echo "/key/swarm/psk/1.0.0/
/base16/
$SWARM_KEY" > /home/.ipfs/swarm.key

chmod 600 home/.ipfs/swarm.key
echo "swarm key created!!"

sudo chown -R test home/.ipfs/

echo 'ipfs init --profile server'
ipfs init --profile server

echo 'ipfs bootstrap rm --all'
ipfs bootstrap rm --all

echo 'ipfs pin ls --type recursive | cut -d' ' -f1 | xargs -n1 ipfs pin rm'
ipfs pin ls --type recursive | cut -d' ' -f1 | xargs -n1 ipfs pin rm

echo 'ipfs repo gc'
ipfs repo gc

#SETUP IPFS AS SERVICE
cat >>/etc/systemd/system/ipfs.service <<EOL
Description=IPFS Daemon
After=syslog.target network.target remote-fs.target nss-lookup.target
[Service]
Type=simple
ExecStart=/usr/local/bin/ipfs daemon --enable-namesys-pubsub
User=test
[Install]
WantedBy=multi-user.target
EOL
echo "ipfs sevice created."

sudo systemctl daemon-reload
echo "systemctl daemon reloaded."

sudo systemctl enable ipfs
echo "systemctl enbled ipfs"

sudo systemctl start ipfs
echo "systemctl started ipfs"