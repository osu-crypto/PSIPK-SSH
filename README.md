# Portable OpenSSH + PSI Authentication

OpenSSH is a complete implementation of the SSH protocol (version 2) for secure remote login, command execution and file transfer. It includes a client ``ssh`` and server ``sshd``, file transfer utilities ``scp`` and ``sftp`` as well as tools for key generation (``ssh-keygen``), run-time key storage (``ssh-agent``) and a number of supporting programs.

This repository serves as a prototype implementation for PSI authentication in OpenSSH.
See our [paper](https://eprint.iacr.org/2022/740) for more details.

## Documentation

### Server PSI Setup
* To enable PSI authentication on the server, set the option `PsiAuthentication yes` in the `sshd_config` file.
* You can start sshd as you normally would (e.g. `# /usr/sbin/sshd -D`).

### Client PSI Setup
* Start the ssh-agent: `eval $(ssh-agent -s)`
* Generate a key (or use existing ones): `ssh-keygen -t ed22519`
* Add keys to the agent: `ssh-add ~/.ssh/id_ed25519`
* Connect with `ssh user@domain`

Containerization of the server/client for easy installation and testing is work in progress.

### OpenSSH Documentation
The official documentation for OpenSSH are the man pages for each tool:

* [ssh(1)](https://man.openbsd.org/ssh.1)
* [sshd(8)](https://man.openbsd.org/sshd.8)
* [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
* [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
* [scp(1)](https://man.openbsd.org/scp.1)
* [sftp(1)](https://man.openbsd.org/sftp.1)
* [ssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
* [sftp-server(8)](https://man.openbsd.org/sftp-server.8)

## Building Portable OpenSSH

### Dependencies

Portable OpenSSH is built using autoconf and make. It requires a working C compiler, standard library and headers.

``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used, but OpenSSH may be built without it supporting a subset of crypto algorithms.

[zlib](https://www.zlib.net/) is optional; without it transport compression is not supported.

FIDO security token support needs [libfido2](https://github.com/Yubico/libfido2) and its dependencies. Also, certain platforms and build-time options may require additional dependencies; see README.platform for details.

### PSI Dependencies
There are a few additional dependencies for installation
* [osu-crypto/libsodium](https://github.com/osu-crypto/libsodium/)
* [NTL](https://libntl.org/)
