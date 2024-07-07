// main.go

package main

import (
	"context"
	"fmt"
	"log"

	"go-jwt-auth/config"
	"go-jwt-auth/docs"
	"go-jwt-auth/internal/rest-api/controllers"
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/repositories"
	"go-jwt-auth/internal/rest-api/services"

	"github.com/MarceloPetrucio/go-scalar-api-reference"
	trmgorm "github.com/avito-tech/go-transaction-manager/drivers/gorm/v2"
	"github.com/avito-tech/go-transaction-manager/trm/v2"
	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
	"github.com/avito-tech/go-transaction-manager/trm/v2/settings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// @title			Go JWT Auth API
// @version		1.0
// @description	Go JWT Auth API example

// @contact.name	Marsel Abazbekov
// @contact.url	https://github.com/GravityTwoG
// @contact.email	marsel.ave@gmail.com

// @host						localhost:8080
// @BasePath					/api
// @securitydefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
// @description Type "Bearer" followed by a space and JWT token.
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

	// Swagger docs
	docs.SwaggerInfo.Host = cfg.Domain
	// read swagger.json
	swaggerSpec := docs.SwaggerInfo.ReadDoc()

	r.GET("/swagger/*any", func(ctx *gin.Context) {
		htmlContent, err := scalar.ApiReferenceHTML(&scalar.Options{
			SpecContent: swaggerSpec,
			DarkMode:    true,
			CustomOptions: scalar.CustomOptions{
				PageTitle: "Go JWT Auth API",
			},
		})

		if err != nil {
			fmt.Printf("%v", err)
		}

		fmt.Fprintln(ctx.Writer, htmlContent)
	})

	// Start server
	r.Run(fmt.Sprintf(":%s", cfg.Port))
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = allowedOrigins
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization")
	return cors.New(corsConfig)
}
