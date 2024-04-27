package app

import (
	"github.com/boogdann/VPN/server/internal/config"
	"github.com/boogdann/VPN/server/internal/message"
	"github.com/boogdann/VPN/server/internal/sniffer"
	"log/slog"
	"math/rand"
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

	msgs := message.New(cfg, []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1}, rand.Uint32(), log)

	// snif := sniffer.New("wlp1s0", 65535, msgs, cfg, log)
	snif := sniffer.New("lo", 65535, msgs, cfg, log)

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
