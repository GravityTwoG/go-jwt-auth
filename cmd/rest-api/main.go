// main.go

package main

import (
	"context"
	"fmt"
	"log"

	"go-jwt-auth/docs"
	"go-jwt-auth/internal/rest-api/config"
	"go-jwt-auth/internal/rest-api/controllers"
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/repositories"
	"go-jwt-auth/internal/rest-api/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title			Go JWT Auth API
// @version		1.0
// @description	Go JWT Auth API example

// @contact.name	Marsel Abazbekov
// @contact.url	https://github.com/GravityTwoG
// @contact.email	marsel.ave@gmail.com

// @host						localhost:8080
// @BasePath					/
// @securitydefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
func main() {
	r := gin.Default()

	r.Use(corsMiddleware([]string{"http://localhost:5173"}))

	cfg := config.MustLoadConfig()

	db, err := database.ConnectToDB(cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}

	userRepo := repositories.NewUserRepository(db)
	refreshTokenRepo := repositories.NewRefreshTokenRepository(db)

	userService := services.NewUserService(userRepo)
	authService := services.NewAuthService(
		userService,
		refreshTokenRepo,
		cfg.JWTSecretKey,
		cfg.JWTAccessTTLsec,
		cfg.RefreshTokenTTLsec,
	)

	authController := controllers.NewAuthController(
		authService,
		cfg.JWTSecretKey,
	)

	authController.RegisterRoutes(r)

	ctx := context.Background()
	ctxCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	go authService.RunScheduledTasks(ctxCancel)

	// you must import docs for swagger to work
	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(
		swaggerFiles.Handler,
	))

	r.Run(fmt.Sprintf(":%s", cfg.Port))
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = allowedOrigins
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization")
	return cors.New(corsConfig)
}
