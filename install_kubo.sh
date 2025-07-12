#!/bin/bash
echo "ipfs install"
# . "$HOME/.bash_profile"
echo 'sudo apt update'
sudo apt update -y

echo 'sudo apt upgrade'
sudo apt upgrade -y

export SWARM_KEY=$(tr -dc a-f0-9 </dev/urandom | head -c 64; echo '')
echo "Created secret: $SWARM_KEY"

export LIBP2P_FORCE_PNET=1

# Use environment variable for IPFS path, default to /home/test/.ipfs for development
export PINTHEON_DATA_DIR=${PINTHEON_DATA_DIR:-/home/test}
export PINTHEON_IPFS_PATH=${PINTHEON_IPFS_PATH:-$PINTHEON_DATA_DIR/.ipfs}

echo "Using IPFS_PATH: $PINTHEON_IPFS_PATH"
echo 'export IPFS_PATH='$PINTHEON_IPFS_PATH >>~/.profile
source ~/.profile

echo "IPFS_PATH:"
echo "$IPFS_PATH"

ver="v0.31.0" 
echo 'wget https://dist.ipfs.tech/kubo/v0.31.0/kubo_v0.31.0_linux-amd64.tar.gz'
wget https://dist.ipfs.tech/kubo/v0.31.0/kubo_v0.31.0_linux-amd64.tar.gz

echo 'tar -xvzf kubo_v0.31.0_linux-amd64.tar.gz'
tar -xvzf kubo_v0.31.0_linux-amd64.tar.gz

echo './kubo/install.sh'
./kubo/install.sh

#sudo bash $HOME/kubo/install.sh
ipfs --version

# Ensure IPFS directory exists
mkdir -p $IPFS_PATH

#CREATE THE SWARM KEY
echo "/key/swarm/psk/1.0.0/
/base16/
$SWARM_KEY" > $IPFS_PATH/swarm.key

chmod 600 $IPFS_PATH/swarm.key
echo "swarm key created!!"

sudo chown -R test $IPFS_PATH

echo 'ipfs init --profile=server'
ipfs init --profile=server

echo 'ipfs bootstrap rm --all'
ipfs bootstrap rm --all

echo 'ipfs pin ls --type recursive | cut -d' ' -f1 | xargs -n1 ipfs pin rm'
ipfs pin ls --type recursive | cut -d' ' -f1 | xargs -n1 ipfs pin rm

echo 'ipfs repo gc'
ipfs repo gc

echo 'ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8082'
ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8082

echo 'ipfs config Gateway.PublicGateways '
ipfs config Gateway.PublicGateways --json '{"localhost": null }'

#SETUP IPFS AS SERVICE
echo "Creating Kubo service"
cat > /etc/systemd/system/ipfs.service <<  EOF
[Unit]
Description=Kubo Service
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
User=test
WorkingDirectory=$IPFS_PATH
ExecStart=/usr/local/bin/ipfs daemon
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "ipfs sevice created."

sudo chown -R test $IPFS_PATH
source ~/.profile

sudo systemctl daemon-reload
echo "systemctl daemon reloaded."

sudo systemctl enable ipfs
echo "systemctl enbled ipfs"

sudo systemctl start ipfs
echo "systemctl started ipfs"