#!/bin/bash
# Launcher for VHS — sources mock environment then drops into interactive bash
DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/demo-env.sh"
exec bash --norc --noprofile -i
