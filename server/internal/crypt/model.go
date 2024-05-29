package crypt

import (
	"fmt"
	"github.com/boogdann/VPN/server/internal/config"
	"log/slog"
)

const (
	startCheckSumIPv6 = 60
	startCheckSumIPv4 = 24
	espHeaderSize     = 4 * 2
)

var (
	ErrInvalidKeySize = fmt.Errorf("invalid key size")
)

type Crypter struct {
	config *config.Config
	key    []byte
	spi    uint32
	log    *slog.Logger
}

func New(config *config.Config, key []byte, spi uint32, log *slog.Logger) *Crypter {
	return &Crypter{
		config: config,
		key:    key,
		spi:    spi,
		log:    log.With(slog.String("op", "crypt")),
	}
}
