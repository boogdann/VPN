package csum

import (
	"encoding/binary"
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
