BINARY = crypgo
TARGET = $(BINARY)
DIST = dist
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# analysis tools, run with go run: nothing to install, go.mod untouched
STATICCHECK = honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK = golang.org/x/vuln/cmd/govulncheck@v1.9.0

all: build

build:
	go build -o $(TARGET) .

test:
	go test ./...

check:
	go vet ./...
	go run $(STATICCHECK) ./...
	go run $(GOVULNCHECK) ./...
	go test -race ./...

run: build
	./$(TARGET)

fmt:
	gofmt -w .

clean:
	go clean

release:
	rm -rf $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ $$os = windows ] && ext=.exe; \
		echo "$(BINARY)-$$os-$$arch$$ext"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o $(DIST)/$(BINARY)-$$os-$$arch$$ext . || exit 1; \
	done

fclean: clean
	rm -f $(TARGET)
	rm -rf $(DIST)

re: fclean all

.PHONY: all build test check run fmt clean release fclean re