package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

const udpPayloadOffset = 44

func (c *Crypter) Decrypt(packet gopacket.Packet) (_ []byte, _err error) {
	defer func() {
		if r := recover(); r != nil {
			_err = fmt.Errorf("panic: %v", r)
		}
	}()

	espLayer := packet.Data()[udpPayloadOffset : len(packet.Data())-sha512.Size256]
	msgMAC := packet.Data()[len(packet.Data())-sha512.Size256:]

	mac := hmac.New(sha512.New512_256, c.key)
	mac.Write(espLayer)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(msgMAC, expectedMAC) {
		return nil, fmt.Errorf("invalid mac")
	}

	iv := espLayer[8 : 8+aes.BlockSize]
	payload := espLayer[8+aes.BlockSize:]
	if len(payload)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid payload length")
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("invalid key size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(payload, payload)

	nextHeader := int(payload[len(payload)-1])
	padLength := int(payload[len(payload)-2])

	var srcMAC, dstMAC net.HardwareAddr
	if c.config.Type == "client" {
		srcMAC = c.config.Client.MAC
		dstMAC = c.config.Server.MAC
	} else {
		srcMAC = c.config.Client.MAC
		dstMAC = c.config.Server.MAC
	}

	var newPacket []byte
	switch nextHeader {
	case int(layers.IPProtocolIPv4):
		newPacket, err = c.buildIpv4Packet(srcMAC, dstMAC, payload[:len(payload)-2-padLength])
	case int(layers.IPProtocolIPv6):
		newPacket, err = c.buildIpv6Packet(srcMAC, dstMAC, payload[:len(payload)-2-padLength])
	}

	if err != nil {
		return nil, err
	}

	fmt.Println("E", newPacket)
	return newPacket, nil
}

func (c *Crypter) buildIpv4Packet(srcMAC, dstMAC net.HardwareAddr, payload []byte) ([]byte, error) {
	newPacket := gopacket.NewSerializeBuffer()
	packetPayload := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)

	//
	return payload, nil
	//
	ipLayer, ok := packetPayload.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("invalid packet type")
	}

	var srcIP, dstIP net.IP
	if c.config.Type == "client" {
		srcIP = ipLayer.SrcIP
		dstIP = c.config.Client.IPv4
	} else {
		srcIP = c.config.Client.IPv4
		dstIP = ipLayer.DstIP
	}

	ipLayer.SrcIP = srcIP
	ipLayer.DstIP = dstIP

	if udp, ok := packetPayload.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && udp != nil {
		if err := udp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			return nil, err
		}

		err := gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			ipLayer,
			udp,
			gopacket.Payload(udp.LayerPayload()),
		)
		if err != nil {
			return nil, err
		}

		return newPacket.Bytes(), nil
	} else {
		tcp, ok := packetPayload.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || tcp == nil {
			return nil, fmt.Errorf("invalid packet type")
		}

		if err := tcp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			return nil, err
		}

		err := gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			ipLayer,
			tcp,
			gopacket.Payload(tcp.LayerPayload()),
		)
		if err != nil {
			return nil, err
		}

		return newPacket.Bytes(), nil
	}
}

func (c *Crypter) buildIpv6Packet(srcMAC, dstMAC net.HardwareAddr, payload []byte) ([]byte, error) {
	newPacket := gopacket.NewSerializeBuffer()
	packetPayload := gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default)

	ipLayer, ok := packetPayload.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		return nil, fmt.Errorf("invalid packet type")
	}

	var srcIP, dstIP net.IP
	if c.config.Type == "client" {
		srcIP = ipLayer.SrcIP
		dstIP = c.config.Client.IPv6
	} else {
		srcIP = c.config.Client.IPv6
		dstIP = ipLayer.DstIP
	}

	ipLayer.SrcIP = srcIP
	ipLayer.DstIP = dstIP

	if udp, ok := packetPayload.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && udp != nil {
		if err := udp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			return nil, err
		}

		err := gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv6,
			},
			ipLayer,
			udp,
			gopacket.Payload(udp.LayerPayload()),
		)
		if err != nil {
			return nil, err
		}

		return newPacket.Bytes(), nil
	} else {
		tcp, ok := packetPayload.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || tcp == nil {
			return nil, fmt.Errorf("invalid packet type")
		}

		if err := tcp.SetNetworkLayerForChecksum(ipLayer); err != nil {
			return nil, err
		}

		err := gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv6,
			},
			ipLayer,
			tcp,
			gopacket.Payload(tcp.LayerPayload()),
		)
		if err != nil {
			return nil, err
		}

		return newPacket.Bytes(), nil
	}
}
