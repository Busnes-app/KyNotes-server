.PHONY: build test vet fmt

# Empty locally; CI uses complementary -run/-skip filters.
TEST_FILTER ?=

build: pqwasm
	CGO_ENABLED=0 go build -trimpath -o kynotes-server ./cmd/kynotes-server

test: pqwasm
	# Keep real passwords and the hang budget; bound package contention.
	go test -race -count=1 -timeout 20m -p 2 $(TEST_FILTER) ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

.PHONY: pqwasm
pqwasm:
	bash scripts/build-pqwasm.sh
