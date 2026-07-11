# Reproducible build flags: no cgo, no paths, no build id.
GOFLAGS = -trimpath -ldflags="-s -w -buildid="

.PHONY: build build-windows test

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o wg-ssh-proxy ./cmd/wg-ssh-proxy

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o wg-ssh-proxy.exe ./cmd/wg-ssh-proxy

test:
	go vet ./...
	go test ./...
