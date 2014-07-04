#!/bin/sh

# Always create version string for repository this script lies in,
# not the cwd... Makes usage easier in cmake
ARG0="$0"
SELF="$(readlink -f "${ARG0}")"
ROOT_DIR="$(dirname "${SELF}")"
cd "$ROOT_DIR"

[ -n "$(git diff)" ] && MODDED='+MOD'

echo $(git describe)$MODDED, branch $(git rev-parse --abbrev-ref HEAD), built "$(date +%Y-%m-%d)"

