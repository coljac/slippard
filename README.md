# Slippard

A simple CLI key-value store that uses your SSH key for encryption.

Slippard stores key-value pairs in an encrypted file, using your existing RSA SSH key for encryption. No extra passwords or key management needed.

## Installation

### Quick install (Linux/macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/coljac/slippard/main/install.sh | sh
```

This installs the latest release to `~/.local/bin`.

### With Go

```sh
go install github.com/coljac/slippard/cmd/slpd@latest
```

### Manual

Download a binary from the [Releases page](https://github.com/coljac/slippard/releases) and place it in your `PATH`.

## Usage

```
slpd set KEY value          # store a value
slpd set KEY=value          # alternative syntax
slpd set KEY                # prompt for the value (hidden input, stays out of shell history)
slpd get KEY                # retrieve a value
slpd del KEY                # delete a key
slpd list                   # list all keys
slpd list <filter>          # list keys matching a substring
slpd dump                   # print all key=value pairs (shell-safe quoting)
slpd help                   # show help
```

Keys are case sensitive.

### Tags

Use `-t <tag>` to organize keys into groups:

```sh
slpd set -t prod DB_HOST=db.example.com
slpd set -t staging DB_HOST=staging-db.local

slpd list -t prod           # only keys tagged "prod"
slpd dump -t prod           # dump only "prod" keys
slpd get -t prod DB_HOST    # get a specific tagged key
```

### Configuration

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `-k <path>` | `SLP_KEY_PATH` | `~/.ssh/id_rsa` | SSH private key |
| `-s <path>` | `SLP_STORE_FILE` | `~/.config/slippard/store.dat` | Encrypted store file |

CLI flags take precedence over environment variables.

## Examples

```sh
# Store a secret without it landing in your shell history
slpd set API_KEY            # prompts, input hidden
pass show api/key | slpd set API_KEY   # or pipe it in

# Fuzzy-find a key
slpd list | fzf | xargs slpd get

# Load a single key into the environment
export API_KEY=$(slpd get API_KEY)

# Load the entire keystore into the environment
export $(slpd dump)

# Use a separate store with a different SSH key
slpd -k ~/.ssh/work_rsa -s ~/work-secrets.dat set TOKEN=abc123
```

## Name

Slippard is named for the Key-slapping Slippard in Dr Seuss' *I Had Trouble Getting to Solla Sollew*.
