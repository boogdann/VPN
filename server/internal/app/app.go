package app

import (
	"github.com/boogdann/VPN/server/internal/config"
	"github.com/boogdann/VPN/server/internal/message"
	"github.com/boogdann/VPN/server/internal/sniffer"
	"log/slog"
	"os"
)

const (
	envLocal = "local"
	envProd  = "prod"
	envDev   = "dev"
)

func Run() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	msgs := message.New(log)

	snif := sniffer.New("eth0", 65535, msgs, cfg, log)

	snif.Start()
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	}
	return log
}
