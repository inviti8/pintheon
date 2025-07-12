#!/bin/bash
cd /home
echo "Installing requirements"
# cd /home/test
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
sudo apt-get install apt-utils
apt update -y
apt upgrade -y
apt install build-essential python3-dev python3.12-venv -y
apt install python3-dev -y
apt install python3-pip -y
apt install python3.12-venv -y
apt-get install libudev-dev
apt install libnss3-tools

apt-get install gcc -y

source ~/.profile

curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v1.4.4-linux-amd64
cp mkcert-v1.4.4-linux-amd64 /usr/local/bin/mkcert

echo "Cloning pintheon"
git clone https://github.com/inviti8/pintheon.git
echo "------------------------------------"
echo "$PWD"
echo "$(ls)"
echo "------------------------------------"
echo "Creating Env"
python3 -m venv pintheon/pintheon
echo "refresh the shell"
source ~/.profile
echo "Activating Env"
source /home/pintheon/pintheon/bin/activate
echo "Installing requirements:"
pip install -r /home/pintheon/requirements.txt
echo "Deactivate the environment"
deactivate
usermod -a -G root www-data
chmod +x pintheon/setup_apptainer.sh
./pintheon/setup_apptainer.sh
# chmod +x pintheon/install_kubo_apptainer.sh
# ./pintheon/install_kubo_apptainer.sh
# ufw reset
# ufw default allow outgoing
# ufw default allow incoming
# ufw allow 8080/tcp
# ufw allow 8082/tcp
# ufw allow 4001/tcp #IPFS inter-node communication
# ufw allow 80/tcp #HTTP port for NGINX
# ufw allow 443/tcp #HTTPS port for NGINX with SSL
# ufw enable

