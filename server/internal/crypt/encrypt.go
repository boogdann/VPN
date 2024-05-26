package crypt

import (
	"crypto/aes"
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

func (c *Crypter) Encrypt(packet gopacket.Packet) ([]byte, error) {
	fmt.Println(packet.Data())
	payloadWithTrailer := c.getPayloadWithTrailer(packet)

	cipheredPayload, iv, err := c.cipherPayload(payloadWithTrailer)
	if err != nil {
		c.log.Error("cipher payload", slog.String("error", err.Error()))
		return nil, err
	}

	espPacket, err := c.buildESP(cipheredPayload, iv)
	if err != nil {
		c.log.Error("build esp packet", slog.String("error", err.Error()))
		return nil, err
	}

	return espPacket, nil
}

func (c *Crypter) setCheckSum(b []byte, cs uint16) {
	binary.BigEndian.PutUint16(b[startCheckSum:], cs)
}

func (c *Crypter) getPadding(payloadLen int) int {
	padLen := 0
	if (payloadLen+2)%aes.BlockSize != 0 {
		padLen = 1
		for ((payloadLen + 2 + padLen) % aes.BlockSize) != 0 {
			padLen++
		}
	}
	return padLen
}

func (c *Crypter) cipherPayload(payload []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		c.log.Error("new cipher", slog.String("error", err.Error()))
		return nil, nil, ErrInvalidKeySize
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		c.log.Error("read iv", slog.String("error", err.Error()))
		return nil, nil, err
	}

	_ = block
	//mode := cipher.NewCBCEncrypter(block, iv)
	//mode.CryptBlocks(payload, payload)

	return payload, iv, nil
}

func (c *Crypter) buildESP(payload []byte, iv []byte) ([]byte, error) {
	espLayer := make([]byte, espHeaderSize+aes.BlockSize+len(payload))
	binary.BigEndian.PutUint32(espLayer[:4], c.spi)
	copy(espLayer[8:8+aes.BlockSize], iv)
	copy(espLayer[8+aes.BlockSize:], payload)

	mac := hmac.New(sha512.New512_256, c.key)
	mac.Write(espLayer)
	msgMAC := mac.Sum(nil)

	espPacket := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(espPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       c.config.Client.MAC,
			DstMAC:       c.config.Server.MAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:    6,
			Length:     uint16(8 + len(espLayer) + sha512.Size256),
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      c.config.Client.IPv6,
			DstIP:      c.config.Server.IPv6,
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(c.config.Client.Port),
			DstPort: layers.UDPPort(c.config.Server.Port),
			Length:  uint16(8 + len(espLayer) + sha512.Size256),
		},
		gopacket.Payload(espLayer),
		gopacket.Payload(msgMAC),
	)
	if err != nil {
		c.log.Error("serialize layers", slog.String("error", err.Error()))
		return nil, err
	}

	cs := csum.CalculateUDPIPv6(c.config.Client.IPv6, c.config.Server.IPv6, espPacket.Bytes()[62:])
	c.setCheckSum(espPacket.Bytes(), cs)

	return espPacket.Bytes(), nil
}

func (c *Crypter) getPayloadWithTrailer(packet gopacket.Packet) []byte {
	network := packet.NetworkLayer()
	nextHeader := int(layers.IPProtocolIPv4)
	if network.LayerType() == layers.LayerTypeIPv6 {
		nextHeader = int(layers.IPProtocolIPv6)
	}

	payload := network.LayerPayload()
	payloadLen := len(payload)

	padLength := c.getPadding(payloadLen)
	if padLength > 0 {
		payload = append(payload, make([]byte, padLength)...)
	}

	return append(payload, byte(padLength), byte(nextHeader))
}
