package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net"
	"strconv"
)

const (
	espHeaderSize = 4 * 2
)

var (
	ErrInvalidPacketType = fmt.Errorf("invalid packet type")
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
	network := packet.NetworkLayer()
	_ = network

	transport, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || transport == nil {
		return ErrInvalidPacketType
	}

	nextHeader := int(layers.IPProtocolIPv4)
	if network.LayerType() == layers.LayerTypeIPv6 {
		nextHeader = int(layers.IPProtocolIPv6)
	}

	payload := network.LayerPayload()
	payloadLen := len(payload)

	padLength := 0
	if (payloadLen+2)%aes.BlockSize != 0 {
		padLength = 1
		for ((payloadLen + 2 + padLength) % aes.BlockSize) != 0 {
			padLength++
		}
		padding := make([]byte, padLength)
		payload = append(payload, padding...)
	}

	payloadWithTrailer := append(payload, byte(padLength), byte(nextHeader))

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(payloadWithTrailer, payloadWithTrailer)

	espLayer := make([]byte, espHeaderSize+aes.BlockSize+len(payloadWithTrailer))
	key := binary.LittleEndian.AppendUint32(nil, m.spi)
	copy(espLayer[:4], key)
	copy(espLayer[8:8+aes.BlockSize], iv)
	copy(espLayer[8+aes.BlockSize:], payloadWithTrailer)

	mac := hmac.New(sha512.New512_256, m.key)
	mac.Write(espLayer)
	msgMAC := mac.Sum(nil)

	srcMAC, _ := net.ParseMAC(m.config.Client.MAC)
	dstMAC, _ := net.ParseMAC(m.config.Server.MAC)
	srcIP := net.ParseIP(m.config.Client.IPv6)
	dstIP := net.ParseIP(m.config.Server.IPv6)

	val, _ := strconv.ParseInt(m.config.Client.Port, 10, 32)
	srcPort := layers.UDPPort(val)
	val, _ = strconv.ParseInt(m.config.Server.Port, 10, 32)
	dstPort := layers.UDPPort(val)

	espPacket := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(espPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:    6,
			Length:     uint16(8 + len(espLayer) + sha512.Size256),
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      srcIP,
			DstIP:      dstIP,
		},
		&layers.UDP{
			SrcPort: srcPort,
			DstPort: dstPort,
			Length:  uint16(8 + len(espLayer) + sha512.Size256),
		},
		gopacket.Payload(espLayer),
		gopacket.Payload(msgMAC),
	)

	if err != nil {
		return err
	}

	send(espPacket.Bytes())

	fmt.Println(espPacket)
	return nil
}

func (m *Message) handleUDPPacket(packet gopacket.Packet, send func([]byte)) error {

	return nil
}
