package main

import (
	_ "auth-service/api"
	"auth-service/internal/controller"
	"auth-service/internal/database"
	mailer "auth-service/internal/mail"
	"auth-service/internal/repository"
	"auth-service/internal/route"
	"auth-service/internal/service"
	"auth-service/pkg/config"
	"auth-service/pkg/logger"
	"os"
)

//	@title			Swagger marketplace API
//	@version		1.0
//	@description	This is a sample server marketplace server.

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath	/api
func main() {
	cfg := config.MustLoad()
	log := logger.NewLogger(cfg.Env)
	conn, err := database.NewPostgresStorage(&cfg.PostgresConfig)
	if err != nil {
		panic("can't connect to database")
	}

	tokenRepo := repository.NewTokenRepo(conn, log)
	userRepo := repository.NewUserRepo(conn, log)
	diller := mailer.NewMockMailer()
	scv := service.NewAuthService(tokenRepo, tokenRepo, userRepo, userRepo, diller, log, cfg.Secret)
	auth := controller.NewAuth(scv, log)
	adsRepo := repository.NewAdsRepo(conn, log)
	adsServ := service.NewAdsService(adsRepo, adsRepo, userRepo, log)
	ads := controller.NewAds(adsServ, log)
	routeCfg := route.ControllersConfig{
		Auth: auth,
		Ads:  ads,
	}

	router := route.NewRouter(routeCfg)

	if err := router.Run(":" + cfg.Port); err != nil {
		log.Error("Somthing went wrong with run service", logger.Err(err), "op", "main")
		os.Exit(1)
	}
}
