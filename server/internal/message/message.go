package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/boogdann/VPN/server/internal/csum"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"log/slog"
)

const (
	startCheckSum = 60
	espHeaderSize = 4 * 2
)

var (
	ErrInvalidPacketType = fmt.Errorf("invalid packet type")
	ErrInvalidKeySize    = fmt.Errorf("invalid key size")
)

func (m *Message) Handle(p []byte, send func([]byte)) {
	packet := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)
	switch udp := packet.Layer(layers.LayerTypeUDP); udp {
	case nil: // tcp packet
		m.handleTCPPacket(packet, send)
	default: // udp packet
		m.handleUDPPacket(packet, send)
	}

	// fmt.Println(packet)
}

func (m *Message) handleTCPPacket(packet gopacket.Packet, send func([]byte)) error {
	transport, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || transport == nil {
		m.log.Error("invalid packet type", slog.String("type", "tcp"))
		return ErrInvalidPacketType
	}

	payloadWithTrailer := m.getPayloadWithTrailer(packet)

	cipheredPayload, iv, err := m.cipherPayload(payloadWithTrailer)
	if err != nil {
		m.log.Error("cipher payload", slog.String("error", err.Error()))
		return err
	}

	espPacket, err := m.buildESP(cipheredPayload, iv)
	if err != nil {
		m.log.Error("build esp packet", slog.String("error", err.Error()))
		return err
	}

	send(espPacket)
	m.log.Info("sent packet")

	return nil
}

func (m *Message) handleUDPPacket(packet gopacket.Packet, send func([]byte)) error {

	return nil
}

func (m *Message) setCheckSum(b []byte, cs uint16) {
	binary.BigEndian.PutUint16(b[startCheckSum:], cs)
}

func (m *Message) getPadding(payloadLen int) int {
	padLen := 0
	if (payloadLen+2)%aes.BlockSize != 0 {
		padLen = 1
		for ((payloadLen + 2 + padLen) % aes.BlockSize) != 0 {
			padLen++
		}
	}
	return padLen
}

func (m *Message) cipherPayload(payload []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		m.log.Error("new cipher", slog.String("error", err.Error()))
		return nil, nil, ErrInvalidKeySize
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		m.log.Error("read iv", slog.String("error", err.Error()))
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(payload, payload)

	return payload, iv, nil
}

func (m *Message) buildESP(payload []byte, iv []byte) ([]byte, error) {
	espLayer := make([]byte, espHeaderSize+aes.BlockSize+len(payload))
	binary.BigEndian.PutUint32(espLayer[:4], m.spi)
	copy(espLayer[8:8+aes.BlockSize], iv)
	copy(espLayer[8+aes.BlockSize:], payload)

	mac := hmac.New(sha512.New512_256, m.key)
	mac.Write(espLayer)
	msgMAC := mac.Sum(nil)

	espPacket := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(espPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       m.config.Client.MAC,
			DstMAC:       m.config.Server.MAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:    6,
			Length:     uint16(8 + len(espLayer) + sha512.Size256),
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      m.config.Client.IPv6,
			DstIP:      m.config.Server.IPv6,
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(m.config.Client.Port),
			DstPort: layers.UDPPort(m.config.Server.Port),
			Length:  uint16(8 + len(espLayer) + sha512.Size256),
		},
		gopacket.Payload(espLayer),
		gopacket.Payload(msgMAC),
	)
	if err != nil {
		m.log.Error("serialize layers", slog.String("error", err.Error()))
		return nil, err
	}

	cs := csum.CalculateUDPIPv6(m.config.Client.IPv6, m.config.Server.IPv6, espPacket.Bytes()[62:])
	m.setCheckSum(espPacket.Bytes(), cs)

	return espPacket.Bytes(), nil
}

func (m *Message) getPayloadWithTrailer(packet gopacket.Packet) []byte {
	network := packet.NetworkLayer()
	nextHeader := int(layers.IPProtocolIPv4)
	if network.LayerType() == layers.LayerTypeIPv6 {
		nextHeader = int(layers.IPProtocolIPv6)
	}

	payload := network.LayerPayload()
	payloadLen := len(payload)

	padLength := m.getPadding(payloadLen)
	if padLength > 0 {
		payload = append(payload, make([]byte, padLength)...)
	}

	return append(payload, byte(padLength), byte(nextHeader))
}
