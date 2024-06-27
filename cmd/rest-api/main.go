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

	trmgorm "github.com/avito-tech/go-transaction-manager/drivers/gorm/v2"
	"github.com/avito-tech/go-transaction-manager/trm/v2"
	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
	"github.com/avito-tech/go-transaction-manager/trm/v2/settings"

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
	cfg := config.MustLoadConfig()

	r := gin.Default()

	r.Use(corsMiddleware(cfg.AllowedOrigins))

	db, err := database.ConnectToDB(cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	trManager := manager.Must(
		trmgorm.NewDefaultFactory(db),
		manager.WithSettings(trmgorm.MustSettings(
			settings.Must(
				settings.WithPropagation(trm.PropagationNested))),
		),
	)

	userRepo := repositories.NewUserRepository(
		db,
		trmgorm.DefaultCtxGetter,
	)
	refreshTokenRepo := repositories.NewRefreshTokenRepository(
		db,
		trmgorm.DefaultCtxGetter,
	)

	userService := services.NewUserService(userRepo)
	authService := services.NewAuthService(
		trManager,
		userService,
		refreshTokenRepo,
		cfg.JWTSecretKey,
		cfg.AccessTokenTTLsec,
		cfg.RefreshTokenTTLsec,
	)

	authController := controllers.NewAuthController(
		authService,
		cfg.JWTSecretKey,
		cfg.Domain,
		"/api/auth",
	)

	api := r.Group("/api")
	authController.RegisterRoutes(api.Group("/auth"))

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
