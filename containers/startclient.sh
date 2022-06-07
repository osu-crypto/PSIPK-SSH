#!/bin/bash

set -e

docker network create sshpsi-net || true
docker run --rm -it \
    --mount type=bind,source="$(pwd)/keys/client",target='/home/sshuser/.ssh' \
    --net sshpsi-net \
    --name sshclient \
    psi-client:1.0
