package message

import (
	"github.com/boogdann/VPN/server/internal/config"
	"log/slog"
)

type Message struct {
	config *config.Config
	key    []byte
	spi    uint32
	log    *slog.Logger
}

func New(config *config.Config, key []byte, spi uint32, log *slog.Logger) *Message {
	return &Message{
		config: config,
		key:    key,
		spi:    spi,
		log:    log.With("message."),
	}
}
