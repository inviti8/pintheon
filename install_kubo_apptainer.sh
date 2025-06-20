#!/bin/bash
cd /root
echo "ipfs install"
echo 'sudo apt update'
apt update -y

echo 'sudo apt upgrade'
apt upgrade -y

export SWARM_KEY=$(tr -dc a-f0-9 </dev/urandom | head -c 64; echo '')
echo "Created secret: $SWARM_KEY"

export LIBP2P_FORCE_PNET=1
echo 'export IPFS_PATH=/.ipfs' >>~/.profile
source ~/.profile

echo "IPFS_PATH:"
echo "$IPFS_PATH"

ver="v0.31.0" 
echo 'wget https://dist.ipfs.tech/kubo/v0.34.1/kubo_v0.34.1_linux-amd64.tar.gz'
wget https://dist.ipfs.tech/kubo/v0.34.1/kubo_v0.34.1_linux-amd64.tar.gz

echo 'tar -xvzf kubo_v0.34.1_linux-amd64.tar.gz'
tar -xvzf kubo_v0.34.1_linux-amd64.tar.gz

echo './kubo/install.sh'
./kubo/install.sh

ipfs --version

mkdir -p $IPFS_PATH

#CREATE THE SWARM KEY
echo "/key/swarm/psk/1.0.0/
/base16/
$SWARM_KEY" > $IPFS_PATH/swarm.key

chmod 600 $IPFS_PATH/swarm.key
echo "swarm key created!!"

chown -R root $IPFS_PATH

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

sudo chown -R root $IPFS_PATH
source ~/.profile
