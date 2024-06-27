#!/bin/sh

pwd
ls -lh
stat ./migrate
stat ./go-jwt-auth

echo "Starting migrations"
./migrate

echo "Starting server"
./go-jwt-auth