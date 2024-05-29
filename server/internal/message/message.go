package message

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log/slog"
)

func (m *Message) Handle(packet gopacket.Packet, send func([]byte)) {
	switch udp := packet.Layer(layers.LayerTypeUDP); udp {
	case nil: // tcp packet
		m.handleTCPPacket(packet, send)
	default: // udp packet
		m.handleUDPPacket(packet, send)
	}
}

func (m *Message) handleTCPPacket(packet gopacket.Packet, send func([]byte)) error {
	fmt.Println("S", packet.Data())
	transport, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || transport == nil {
		m.log.Error("invalid packet type", slog.String("type", "tcp"))
		return ErrInvalidPacketType
	}

	go func() {
		bytes, err := m.enc.Encrypt(packet)
		if err != nil {
			m.log.Error("decrypt packet", slog.String("error", err.Error()))
			return
		}

		m.log.Info("received", slog.String("type", "tcp"))
		send(bytes)
	}()

	return nil
}

func (m *Message) handleUDPPacket(packet gopacket.Packet, send func([]byte)) error {
	transport, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || transport == nil {
		m.log.Error("invalid packet type", slog.String("type", "udp"))
		return ErrInvalidPacketType
	}

	if transport.DstPort == layers.UDPPort(m.cfg.Server.Port) {
		go func() {
			m.log.Info("server port", slog.String("port", transport.DstPort.String()))
			bytes, err := m.dec.Decrypt(packet)
			if err != nil {
				m.log.Error("decrypt packet", slog.String("error", err.Error()))
				return
			}

			m.log.Info("received", slog.String("type", "udp"))
			send(bytes)
		}()
	} else {
		go func() {
			m.log.Info("client port", slog.String("port", transport.DstPort.String()))
			bytes, err := m.enc.Encrypt(packet)
			if err != nil {
				m.log.Error("decrypt packet", slog.String("error", err.Error()))
				return
			}

			m.log.Info("sent", slog.String("type", "udp"))
			send(bytes)
		}()
	}

	return nil
}

func (m *Message) Send(packet []byte) {
	fmt.Printf("S %x\n", packet)
	if err := m.handle.WritePacketData(packet); err != nil {
		m.log.Error("sending packet", slog.String("error", err.Error()))
		return
	}

	m.log.Info("sent packet")
	return
}
