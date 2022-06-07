#!/bin/bash

set -e

docker run --rm -it\
    --mount type=bind,source="$(pwd)/config/sshd_config",target='/usr/local/etc/sshd_config' \
    --mount type=bind,source="$(pwd)/keys/server",target='/home/sshuser/.ssh' \
    --net sshpsi-net \
    --name sshserver \
    ghcr.io/osu-crypto/psipk-ssh/psi-server:1.0
