# Stage 1: Build the Go binary
FROM golang:1.22.2 AS build

# Set the working directory
WORKDIR /app

# Copy the Go modules files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the Go application
RUN env GOOS=linux GOARCH=amd64 go build -o go-jwt-auth ./cmd/rest-api/main.go


# Stage 2: Create a minimal image
FROM alpine:latest

# Install necessary certificates
RUN apk --no-cache add ca-certificates

# Set the working directory
WORKDIR /app/

# Copy the Go binary from the build stage
COPY --from=build /app/go-jwt-auth ./go-jwt-auth

# Expose the application's port
EXPOSE 8080

# Command to run the Go application
CMD ["./go-jwt-auth"]
