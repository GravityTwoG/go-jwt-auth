
vet:
	go vet ./...

fmt:
	go fmt ./...

app-build:
	go build -o app.bin ./cmd/rest-api/main.go

app-dockerize:
	docker build -f ./deployments/rest-api-prod/Dockerfile -t go-jwt-auth . 

app-run:
	go run ./cmd/rest-api/main.go

migrate:
	go run ./cmd/migrate/main.go

test:
	go test ./...

test-tparse:
	set -o pipefail && go test -json ./... | tparse -all

coverage: 
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	rm coverage.out

coverage-html: 
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	rm coverage.out

infra:
	cd deployments && docker-compose up

infra-detached:
	cd deployments && docker-compose up -d

infra-down:
	cd deployments && docker-compose down

infra-remove:
	cd deployments && docker-compose down -v

infra-test:
	cd deployments && docker-compose -f docker-compose.test.yaml up

infra-test-detached:
	cd deployments && docker-compose -f docker-compose.test.yaml up -d

infra-test-down:
	cd deployments && docker-compose -f docker-compose.test.yaml down

openapi:
	swag init -g ./internal/rest-api/app/app.go --parseInternal --parseDependency

lint:
	golangci-lint run

hadolint:
	git ls-files --exclude='Dockerfile*' -c --ignored | xargs hadolint

dev: infra-detached migrate infra