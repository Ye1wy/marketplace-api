package logger

import (
	"log/slog"
	"os"
)

const localEnv = "local"

// type Logger interface{}

type Logger struct {
	*slog.Logger
}

func NewLogger(env string) *Logger {
	var log *slog.Logger

	switch env {
	case localEnv:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	return &Logger{
		log,
	}
}

func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   "error",
		Value: slog.StringValue(err.Error()),
	}
}
