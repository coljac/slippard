# slpd — encrypted key-value store

# Build the local binary (./slpd)
build:
    go build -o slpd ./cmd/slpd

# Build and install to ~/.local/bin
install: build
    cp slpd ~/.local/bin/slpd

test:
    go test ./...

# Cross-compiled release artefacts into dist/ (delegates to the Makefile)
release:
    make all
