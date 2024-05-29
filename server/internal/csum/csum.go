package csum

import (
	"encoding/binary"
	"github.com/google/gopacket/layers"
	"net"
)

const (
	sizeHeaderV6 = 40
	protocolUDP  = 17
)

func CalculateUDPIPv6(srcIP, dstIP net.IP, data []byte) uint16 {
	pseudoHeader := make([]byte, sizeHeaderV6)
	copy(pseudoHeader[0:16], srcIP.To16())
	copy(pseudoHeader[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(data)))
	pseudoHeader[39] = protocolUDP

	// maybe set checksum bytes to zero

	var sum uint32
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(pseudoHeader[i])<<8 + uint32(pseudoHeader[i+1])
	}

	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return ^uint16(sum)
}

func CalculateUDPIPv4(srcaddr, dstaddr, udpdata []byte) uint16 {
	var csum uint32
	var udplen uint32 = uint32(len(udpdata))

	// clear checksum bytes
	udpdata[6] = 0
	udpdata[7] = 0

	csum += uint32(srcaddr[0]) << 8
	csum += uint32(srcaddr[1])
	csum += uint32(srcaddr[2]) << 8
	csum += uint32(srcaddr[3])

	csum += uint32(dstaddr[0]) << 8
	csum += uint32(dstaddr[1])
	csum += uint32(dstaddr[2]) << 8
	csum += uint32(dstaddr[3])

	csum += uint32(layers.IPProtocolUDP)
	csum += udplen

	end := len(udpdata) - 1

	for i := 0; i < end; i += 2 {
		csum += uint32(udpdata[i]) << 8
		csum += uint32(udpdata[i+1])
	}

	if len(udpdata)%2 == 1 {
		csum += uint32(udpdata[end]) << 8
	}

	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)

}
