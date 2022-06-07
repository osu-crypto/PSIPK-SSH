#!/bin/bash

# Ensure permissions of keys aren't too open
chmod 700 ./keys/server
chmod 700 ./keys/client

chmod 600 ./keys/server/*
chmod 600 ./keys/client/*

docker pull ghcr.io/osu-crypto/psipk-ssh/psi-server:1.0
docker pull ghcr.io/osu-crypto/psipk-ssh/psi-client:1.0
docker network create sshpsi-net || true
