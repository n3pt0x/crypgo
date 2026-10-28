BINARY = crypgo
TARGET = $(BINARY)
DIST = dist
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

all: build

build:
		go build -o $(TARGET) .

test:
		go test ./...

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
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -o $(DIST)/$(BINARY)-$$os-$$arch$$ext . || exit 1; \
	done

fclean: clean
		rm -f $(TARGET)
		rm -rf $(DIST)

re: fclean all

.PHONY: all build test run fmt clean release fclean re