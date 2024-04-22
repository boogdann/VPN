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
	Handle(packet gopacket.Packet)
}

type Sniffer struct {
	handler      PacketHandler
	config       *config.Config
	name         string
	maxSize      int32
	send         chan gopacket.SerializeBuffer
	recv         chan gopacket.Packet
	isPromcsMode bool

	close chan struct{}
	log   *slog.Logger
}

func New(name string, size int, handler PacketHandler, cfg *config.Config, log *slog.Logger) *Sniffer {
	return &Sniffer{
		config: cfg,

		name:         name,
		maxSize:      int32(size),
		isPromcsMode: true,
		send:         make(chan gopacket.SerializeBuffer, sizeSendChan),
		handler:      handler,

		close: make(chan struct{}, 1),
		log:   log,
	}
}
