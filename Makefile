.PHONY: help test test-coverage lint fmt vet clean build example docker-arango

# Default target
help:
	@echo "Available targets:"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make lint           - Run golangci-lint"
	@echo "  make fmt            - Format code with gofmt"
	@echo "  make vet            - Run go vet"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make example        - Run the basic example"
	@echo "  make docker-arango  - Start ArangoDB in Docker"

# Run tests
test:
	@echo "Running tests..."
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install it from https://golangci-lint.run/usage/install/"; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	gofmt -w -s .

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f coverage.txt coverage.html
	go clean -cache -testcache

# Run the basic example
example:
	@echo "Running basic example..."
	cd examples/basic && go run main.go

# Start ArangoDB in Docker for testing
docker-arango:
	@echo "Starting ArangoDB in Docker..."
	@docker run -d --name arangodb-test \
		-e ARANGO_ROOT_PASSWORD=password \
		-p 8529:8529 \
		arangodb/arangodb:latest
	@echo "ArangoDB started at http://localhost:8529"
	@echo "Username: root"
	@echo "Password: password"
	@echo ""
	@echo "To stop: docker stop arangodb-test"
	@echo "To remove: docker rm arangodb-test"

# Stop and remove Docker container
docker-stop:
	@echo "Stopping ArangoDB..."
	@docker stop arangodb-test || true
	@docker rm arangodb-test || true
