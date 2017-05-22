Flag updater - Client
=====================

**TODO**: This README is under development

## Installation

Run `make`.

### Dependencies

Requires C libraries (found in Aptitude, for instance):
 - `libgpgme`

The client expects a gpg keypair with the following to be in project root:
 - `priv.key`
 - `pub.key`


## Running

The arguments are:
 1. `ip`: flag updater server
 2. `port`: flag updater server
 3. `srv.key`: path to server's public key
 4. `username`: github username of TA
 
### Example

    build/client 127.0.0.1 41 ./srv.pub sangkilc
