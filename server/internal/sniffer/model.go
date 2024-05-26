package sniffer

import (
	"github.com/boogdann/VPN/server/internal/config"
	"github.com/google/gopacket"
	"log/slog"
)

const (
	sizeSendChan = 1
	sizeRecvChan = 1
)

type PacketHandler interface {
	Handle(packet gopacket.Packet, sender func(packet []byte))
}

type Sender interface {
	Send(packet []byte)
}

type Sniffer struct {
	handler PacketHandler
	sender  Sender

	config       *config.Config
	name         string
	maxSize      int32
	send         chan []byte
	isPromcsMode bool

	close chan struct{}
	log   *slog.Logger
}

func New(name string, size int, sender Sender, handler PacketHandler, cfg *config.Config, log *slog.Logger) *Sniffer {
	return &Sniffer{
		config: cfg,

		name:         name,
		maxSize:      int32(size),
		isPromcsMode: true,
		send:         make(chan []byte, sizeSendChan),
		handler:      handler,
		sender:       sender,

		close: make(chan struct{}, 1),
		log:   log,
	}
}
