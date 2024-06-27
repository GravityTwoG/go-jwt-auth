# JWT authorization example on golang

Run whole system using command: `make infra`

Swagger docs located by url: https://jwt-auth-api.abazbekov.ru/swagger/index.html

## Frontend

- https://github.com/GravityTwoG/react-jwt-auth

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
