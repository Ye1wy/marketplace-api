package config

import (
	"auth-service/internal/database"
	mailer "auth-service/internal/mail"
	"log"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env        string `env:"env" env-default:"local"`
	Secret     string `env:"secret_word"`
	HttpServer `env:"server"`
	database.PostgresConfig
	mailer.MailerConfig
}

type HttpServer struct {
	Address string `env:"address" env-default:"localhost"`
	Port    string `env:"port" env-default:"8080"`
}

func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")

	if configPath == "" {
		log.Fatal("CONFIG_PATH is empty")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("There is no file in the CONFIG_PATH path: %v", err)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("Cannot read config file: %v", err)
	}

	return &cfg
}
