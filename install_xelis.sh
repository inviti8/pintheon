#!/bin/env bash
set -eo pipefail
echo "Installing Rust:"
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y
sudo apt install cargo -y
BASE_DIR="${XDG_CONFIG_HOME:-$HOME}"
USER_DIR="${LOCAL_DIR-"$BASE_DIR/test"}"
XELIS_DNLD="$USER_DIR/xelis-blockchain}"
XELIS_RELEASE="$XELIS_DNLD/target/release"
LOCAL_DIR="${LOCAL_DIR-"$BASE_DIR/.local"}"
XELIS_DIR="$LOCAL_DIR/share/xelis-blockchain"
git clone https://github.com/xelis-project/xelis-blockchain
source ~/.profile
sudo chown -R test $XELIS_DNLD
cd xelis-blockchain
echo "Building Xelis:"
cargo build --release
# Create heavymeta directory and hvym binary if it doesn't exist.
mkdir -p "$XELIS_DIR"

mv $XELIS_DNLD* XELIS_DNLD
echo "export xelis to path:"
# Store the correct profile file (i.e. .profile for bash or .zshenv for ZSH).
case $SHELL in
*/zsh)
    PROFILE="${ZDOTDIR-"$HOME"}/.zshenv"
    PREF_SHELL=zsh
    ;;
*/bash)
    PROFILE=$HOME/.bashrc
    PREF_SHELL=bash
    ;;
*/fish)
    PROFILE=$HOME/.config/fish/config.fish
    PREF_SHELL=fish
    ;;
*/ash)
    PROFILE=$HOME/.profile
    PREF_SHELL=ash
    ;;
*)
    echo "could not detect shell, manually add ${XELIS_DIR} to your PATH."
    exit 1
esac

# Only add hvym if it isn't already in PATH.
if [[ ":$PATH:" != *":${XELIS_DIR}:"* ]]; then
    # Add the hvym directory to the path and ensure the old PATH variables remain.
    # If the shell is fish, echo fish_add_path instead of export.
    if [[ "$PREF_SHELL" == "fish" ]]; then
        echo >> "$PROFILE" && echo "fish_add_path -a $XELIS_DIR" >> "$PROFILE"
    else
        echo >> "$PROFILE" && echo "export PATH=\"\$PATH:$XELIS_DIR\"" >> "$PROFILE"
    fi
fi