BINARY = crypgo
TARGET = $(BINARY)

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

fclean: clean
		rm -f $(BIN_DIR) $(TARGET)

re: fclean all

.PHONY: all build test run clean