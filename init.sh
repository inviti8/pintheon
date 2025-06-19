#!/bin/bash
echo "Installing requirements"
sudo apt update -y
sudo apt upgrade -y
sudo apt install build-essential python3-dev python3.12-venv -y
sudo apt install python3-dev -y
sudo apt install python3-pip -y
sudo apt install python3.12-venv -y
sudo apt-get install libudev-dev
sudo apt install libnss3-tools

sudo apt-get install gcc -y
source ~/.profile

curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v1.4.4-linux-amd64
sudo cp mkcert-v1.4.4-linux-amd64 /usr/local/bin/mkcert

echo "Cloning pintheon"
git clone https://github.com/inviti8/pintheon.git
echo "Creating Env"
python3 -m venv pintheon/pintheon
echo "refresh the shell"
source ~/.profile
echo "Activating Env"
source pintheon/pintheon/bin/activate
echo "Installing requirements:"
pip install -r /home/test/pintheon/requirements.txt
echo "Deactivate the environment"
deactivate
usermod -a -G test www-data
chmod +x pintheon/setup.sh
./pintheon/setup.sh
chmod +x pintheon/install_kubo.sh
sudo ./pintheon/install_kubo.sh
export EDITOR=$(which vim)
sudo ufw reset -y
sudo ufw default allow outgoing
sudo ufw default allow incoming
sudo ufw allow 8080/tcp
sudo ufw allow 8082/tcp
sudo ufw allow 4001/tcp #IPFS inter-node communication
sudo ufw allow 80/tcp #HTTP port for NGINX
sudo ufw allow 443/tcp #HTTPS port for NGINX with SSL
sudo ufw enable
echo "refresh the shell"
source ~/.profile
