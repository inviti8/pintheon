#!/bin/sh
DIR="/home/.local/share/xelis-blockchain"

PROFILE=$(basename $SHELL)rc

echo "export PATH=\"\$PATH:$DIR\"" >> ~/.$PROFILE
