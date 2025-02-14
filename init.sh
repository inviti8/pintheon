#!/bin/bash
echo "Installing requirements"
sudo apt update -y
sudo apt upgrade -y
sudo apt install build-essential python3-dev python3.12-venv -y
sudo apt install python3-dev -y
sudo apt install python3-pip -y
sudo apt install python3.12-venv -y

sudo apt-get install gcc
source ~/.profile

echo "Cloning axiel"
git clone https://github.com/inviti8/axiel.git
git clone https://github.com/xelis-project/xelis-paper-wallet.git
cp -r xelis-paper-wallet/xelis-paper-wallet/ /home/test/axiel/
echo "Creating Env"
python3 -m venv axiel/axiel
echo "refresh the shell"
source ~/.profile
echo "Activating Env"
source axiel/axiel/bin/activate
echo "Installing requirements:"
pip install -r /home/test/axiel/requirements.txt
echo "Deactivate the environment"
deactivate
chmod +x axiel/xelis_wallet_gen.sh
chmod +x axiel/setup.sh
usermod -a -G test www-data
./axiel/xelis_wallet_gen.sh
./axiel/setup.sh
chmod +x axiel/install_xelis.sh
chmod +x axiel/install_kubo.sh
chmod +x axiel/update_path.sh
./axiel/install_xelis.sh
sudo ./axiel/install_kubo.sh