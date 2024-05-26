package message

import (
	"fmt"
	"github.com/boogdann/VPN/server/internal/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log/slog"
)

var (
	ErrInvalidPacketType = fmt.Errorf("invalid packet type")
)

type Encrypter interface {
	Encrypt(packet gopacket.Packet) ([]byte, error)
}

type Decrypter interface {
	Decrypt(packet gopacket.Packet) ([]byte, error)
}

type Message struct {
	handle *pcap.Handle
	cfg    *config.Config
	enc    Encrypter
	dec    Decrypter
	log    *slog.Logger
}

func New(cfg *config.Config, enc Encrypter, dec Decrypter, log *slog.Logger) *Message {
	handle, err := pcap.OpenLive(cfg.SendInfName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Error("Open network interface",
			slog.String("error", err.Error()))
		return nil
	}

	return &Message{
		handle: handle,
		cfg:    cfg,
		enc:    enc,
		dec:    dec,
		log:    log.With(slog.String("op", "message")),
	}
}

func (m *Message) Close() {
	m.handle.Close()
}
