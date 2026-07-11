# -trimpath drops the builder's local paths from the binary; -s -w strips
# symbols and debug info.
GOFLAGS = -trimpath -ldflags="-s -w"

.PHONY: build build-windows test

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o wg-ssh-proxy ./cmd/wg-ssh-proxy

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o wg-ssh-proxy.exe ./cmd/wg-ssh-proxy

test:
	test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...
	go test ./...
