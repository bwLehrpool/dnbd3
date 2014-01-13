#!/bin/sh

[ -n "$(git diff)" ] && MODDED='+MOD'

echo $(git describe)$MODDED, branch $(git rev-parse --abbrev-ref HEAD), built "$(date +%Y-%m-%d)"

