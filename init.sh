#!/bin/bash
echo "Installing requirements"
sudo apt update -y
sudo apt upgrade -y
sudo apt install build-essential python3-dev python3.12-venv -y
sudo apt install python3-dev -y
sudo apt install python3-pip -y
sudo apt install python3.12-venv -y

sudo apt-get install gcc -y
source ~/.profile

echo "Cloning philos"
git clone https://github.com/inviti8/philos.git
echo "Creating Env"
python3 -m venv philos/philos
echo "refresh the shell"
source ~/.profile
echo "Activating Env"
source philos/philos/bin/activate
echo "Installing requirements:"
pip install -r /home/test/philos/requirements.txt
echo "Deactivate the environment"
deactivate
chmod +x philos/xelis_wallet_gen.sh
chmod +x philos/setup.sh
usermod -a -G test www-data
./philos/xelis_wallet_gen.sh
./philos/setup.sh
chmod +x philos/install_xelis.sh
chmod +x philos/install_kubo.sh
chmod +x philos/update_path.sh
./philos/install_xelis.sh
sudo ./philos/install_kubo.sh