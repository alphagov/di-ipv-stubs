#!/usr/bin/env bash
set -eu

CONFIG_DIR="../../di-ipv-config/stubs/di-ipv-core-stub"

if [ ! -d "$CONFIG_DIR" ]; then
  { echo "🛑 config dir '$CONFIG_DIR' does not exist in expected location"; exit 1; }
fi

docker build -t ipv-core-stub .
docker run -p 8085:8085 --env-file ${CONFIG_DIR}/.env --mount type=bind,source="$(pwd)/$CONFIG_DIR",target=/app/config ipv-core-stub
