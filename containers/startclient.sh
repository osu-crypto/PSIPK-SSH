#!/bin/bash

set -e

docker run --rm -it \
    --mount type=bind,source="$(pwd)/keys/client",target='/home/sshuser/.ssh' \
    --net sshpsi-net \
    --name sshclient \
    ghcr.io/osu-crypto/psipk-ssh/psi-client:1.0
