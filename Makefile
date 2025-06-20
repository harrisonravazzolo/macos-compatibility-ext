.PHONY: build clean test install

# Build the extension
build:
	go build -o macos_compatibility.ext

# Clean build artifacts
clean:
	rm -f macos_compatibility.ext
	rm -rf /private/var/tmp/sofa/

# Run tests (if any)
test:
	go test ./...

# Install dependencies
deps:
	go mod tidy
	go mod download

# Build for production (with optimizations)
build-prod:
	CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo -ldflags="-s -w" -o macos_compatibility.ext

# Install to system location (requires sudo)
install: build
	sudo mkdir -p /usr/local/osquery_extensions/
	sudo cp macos_compatibility.ext /usr/local/osquery_extensions/
	sudo chown root:wheel /usr/local/osquery_extensions/macos_compatibility.ext
	sudo chmod 755 /usr/local/osquery_extensions/macos_compatibility.ext

# Create extensions load file
extensions-load:
	echo "/usr/local/osquery_extensions/macos_compatibility.ext" > /tmp/extensions.load

# Help target
help:
	@echo "Available targets:"
	@echo "  build        - Build the extension"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  deps         - Install dependencies"
	@echo "  build-prod   - Build optimized version"
	@echo "  install      - Install to system location"
	@echo "  extensions-load - Create extensions load file"
	@echo "  help         - Show this help" 