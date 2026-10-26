.PHONY: build test vet fmt

build:
	CGO_ENABLED=0 go build -trimpath -o kynotes-server ./cmd/kynotes-server

test:
	# The real-password API suite can exceed Go's ten-minute package default.
	go test -race -count=1 -timeout 20m ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
