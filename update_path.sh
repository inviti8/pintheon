#!/usr/bin/bash
set -eo pipefail
echo "Updating path:"
BASE_DIR="${XDG_CONFIG_HOME:-$HOME}"
LOCAL_DIR="${LOCAL_DIR-"$BASE_DIR/.local"}"
XELIS_DIR="$LOCAL_DIR/share/xelis-blockchain"

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
    echo "could not detect shell, manually add ${PRESS_DIR} to your PATH."
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