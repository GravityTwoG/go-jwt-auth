package app

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
	"go-jwt-auth/internal/rest-api/services/oauth"

	"github.com/MarceloPetrucio/go-scalar-api-reference"
	trmgorm "github.com/avito-tech/go-transaction-manager/drivers/gorm/v2"
	"github.com/avito-tech/go-transaction-manager/trm/v2"
	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
	"github.com/avito-tech/go-transaction-manager/trm/v2/settings"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

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
func Run() {
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

	userAuthProviderRepo := repositories.NewUserAuthProviderRepository(
		db,
		trmgorm.DefaultCtxGetter,
	)

	privateKey, err := services.ParseRSAKey(
		cfg.JWTPrivateKey,
	)
	if err != nil {
		log.Fatal("Error parsing RSA key: ", err)
	}

	jwtService := services.NewJWTService(privateKey)

	googleOAuthService := oauth.NewGoogleOAuthService(
		cfg.GoogleClientID,
		cfg.GoogleClientSecret,
	)

	githubOAuthService := oauth.NewGitHubOAuthService(
		cfg.GitHubClientID,
		cfg.GitHubClientSecret,
	)

	authService := services.NewAuthService(
		trManager,

		userRepo,
		refreshTokenRepo,
		userAuthProviderRepo,
		jwtService,

		cfg.AccessTokenTTLsec,
		cfg.RefreshTokenTTLsec,

		map[string]oauth.OAuthService{
			"google": googleOAuthService,
			"github": githubOAuthService,
		},
	)

	api := r.Group("/api")
	controllers.NewAuthController(
		api,
		authService,
		&privateKey.PublicKey,
		cfg.Domain,
		"/api/auth",
	)

	ctxCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	go authService.RunScheduledTasks(ctxCancel)

	// Swagger docs
	if cfg.Domain == "localhost" {
		docs.SwaggerInfo.Host = "localhost:" + cfg.Port
	} else {
		docs.SwaggerInfo.Host = cfg.Domain
	}
	docs.SwaggerInfo.Schemes = []string{"https", "http"}
	docs.SwaggerInfo.BasePath = "/api"
	// read swagger.json
	swaggerSpec := docs.SwaggerInfo.ReadDoc()

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.GET("/scalar/*any", func(ctx *gin.Context) {
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
	err = r.Run(fmt.Sprintf(":%s", cfg.Port))
	fmt.Println("r.Run ", err)
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = allowedOrigins
	corsConfig.AllowCredentials = true
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization")
	return cors.New(corsConfig)
}
