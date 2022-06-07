# SSH-PSI Artifact Evaluation

## Dependencies
- A Unix System
- Docker

## Quickstart
- Make sure you are running all the commands from this directory
- Begin be running `setup.sh` to pull the required containers and setup a docker network.
- Start the server instance with `startserver.sh` in the background
- Open another terminal and get access to the client with `startclient.sh`: you will be place in a shell inside the container
- Run `source setupkeys.sh` inside the container to add all private keys from `~/.ssh` into our `ssh-agent`
- Ensure you can connect to the server with `ssh sshserver`: if the connection is successful, you will see "Authenticating with PSI"
- Feel free to try different key configurations by changing the keys of the server/client in the `keys/` directory.
