# Slippard: Simple CLI key-value store, which uses your SSH key for encryption.

Slippard is designed to store text blobs against a key value, and to store the data in a secure, encrypted way.

# Installation

If you have go installed, `go get github.com/coljac/slippard/cmd/slpd@latest`.

Download a binary from the Releases page and put in your path.

# Usage

Slippard by default stores data in `$HOME/.config/slippard/store.dat` and encrypts/decrypts with `$HOME/.ssh/id_rsa`.

Setting a key:

`slpd set KEY=value` or `slpd set KEY value`

Getting a key:

`slpd get KEY`

Finding a key:

`slpd list`, `slpd list <string>`

Getting all keys and values:

`slpd dump`

which returns 

```
KEY1=value1
KEY2=value2
...
```

Keys are case sensitive.

# Tags

If you specify a tag when setting, listing, or dumping keys, the action will be filtered by that tag. Tags are specified with the `-t` option. For instance, `slpd set -t env KEY=VAL` will mean that `KEY` is returned from `slpd list -t env`, but all other keys set without that tag will be omitted.

# Configuration

The location of the key store can be overrided from the default of `~/.config/slippard/store.dat` with the `SLP_STORE_FILE` environment variable. The SSH key can be overridden from the default of `~/.ssh/id_rsa` with the `SLP_KEY_PATH` variable.

# Examples

`slpd list | fzf | xargs slpd get` to fuzzy-find a key

`export KEY=$(slpd get KEY)` in .bashrc

`export $(slpd dump| xargs)` to add the whole keystore to the environment


# TODOs

- Better help and options
- Linux package manager versions

## Name

Slippard is named for the Key-slapping Slippard in Dr Seuss' *I had Trouble Getting to Solla Sollew*.
