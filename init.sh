#!/bin/bash
echo "Installing requirements"
sudo apt update -y
sudo apt upgrade -y
sudo apt install build-essential python3-dev python3.12-venv -y
sudo apt install python3-dev -y
sudo apt install python3-pip -y
sudo apt install python3.12-venv -y

echo "Cloning axiel"
git clone https://github.com/inviti8/axiel.git
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
echo "Owning the directory"
sudo chown -R test /home/
chmod +x axiel/setup.sh
./axiel/setup.sh