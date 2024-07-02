# Stage 1: Build the Go binary
FROM golang:1.22.2 AS build

# Set the working directory
WORKDIR /app

# Copy the Go modules files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o migrate ./cmd/migrate/main.go

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o go-jwt-auth ./cmd/rest-api/main.go


# Stage 2: Create a minimal image
FROM alpine:latest

# Install necessary certificates
RUN apk --no-cache add ca-certificates

# Set the working directory
WORKDIR /app/

# Copy the Go binary from the build stage
COPY --from=build /app/migrate ./cmd/migrate/migrate
COPY --from=build /app/go-jwt-auth ./cmd/rest-api/go-jwt-auth
COPY --from=build /app/docs/swagger.json ./docs/swagger.json
COPY --from=build /app/deployments/rest-api-prod/startup.sh ./startup.sh

RUN chmod +x ./startup.sh

# Expose the application's port
EXPOSE 8080

# Command to run the Go application
CMD ["sh", "-c", "./startup.sh"]
