#!/bin/sh

pwd
ls -lh
stat ./cmd/migrate/migrate
stat ./cmd/rest-api/go-jwt-auth

echo "Starting migrations"
cd /app/cmd/migrate
./migrate

echo "Starting server"
cd /app/cmd/rest-api
./go-jwt-auth