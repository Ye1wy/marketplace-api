package main

import (
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
	router := route.NewRouter(auth)

	if err := router.Run(":" + cfg.Port); err != nil {
		log.Error("Somthing went wrong with run service", logger.Err(err), "op", "main")
		os.Exit(1)
	}
}
