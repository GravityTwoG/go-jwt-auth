// main.go

package main

import (
	"fmt"
	"log"

	"go-jwt-auth/internal/rest-api/config"
	"go-jwt-auth/internal/rest-api/controllers"
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/repositories"
	"go-jwt-auth/internal/rest-api/services"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	cfg := config.MustLoadConfig()

	db, err := database.ConnectToDB(cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}

	userRepo := repositories.NewUserRepository(db)
	userService := services.NewUserService(userRepo)
	authService := services.NewAuthService(
		userService,
		cfg.JWTSecretKey,
		cfg.JWTExpirationMillis,
	)

	authController := controllers.NewAuthController(
		authService,
		cfg.JWTSecretKey,
	)

	authController.RegisterRoutes(r)

	r.Run(fmt.Sprintf(":%s", cfg.Port))
}
