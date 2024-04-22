package app

import (
	"github.com/boogdann/VPN/server/internal/config"
	"github.com/boogdann/VPN/server/internal/message"
	"github.com/boogdann/VPN/server/internal/sniffer"
)

func Run() {
	cfg := config.MustLoad()

	msgs := message.New()

	snif := sniffer.New("eth0", 65535, msgs, cfg)

	snif.Start()
}
