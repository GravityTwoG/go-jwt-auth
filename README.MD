# JWT authorization example on golang

Run whole system using command: `make infra`

Swagger docs located by url: http://localhost:8080/swagger/index.html

# Folder structure

- cmd - entry files for rest-api and migrator
- internal - internal packages
- - rest-api
- - - config - load config from .env
- - - database - db context
- - - models - database models
- - - repositories - data access layer
- - - entities - domain specific
- - - services - domain specific services
- - - controllers - REST controllers
- - - dto - Data transfer objects
- deployments - docker and docker compose files
- docs - swagger docs
