BINARY := tunl
GOFLAGS := -trimpath -ldflags="-s -w"

.PHONY: build clean test lint test-docker integration-test

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BINARY) .

clean:
	rm -f $(BINARY)

test:
	go test -race ./internal/...

lint:
	go vet ./...
	staticcheck ./...
	gosec -quiet ./...
	govulncheck ./...

test-docker:
	docker build -t tunl-test -f Dockerfile.test .
	docker run --rm tunl-test go test -race ./internal/...
	$(MAKE) integration-test

integration-test:
	docker compose -f docker-compose.test.yml build
	docker compose -f docker-compose.test.yml up --abort-on-container-exit --exit-code-from client; \
		rc=$$?; \
		docker compose -f docker-compose.test.yml down -v --remove-orphans; \
		exit $$rc

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

uninstall:
	rm -f /usr/local/bin/$(BINARY)
