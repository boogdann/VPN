package sniffer

import (
	"github.com/google/gopacket/pcap"
)

func (s *Sniffer) Start() {
	s.listenInterface()
}

func (s *Sniffer) listenInterface() error {
	handle, err := pcap.OpenLive(s.name, int32(s.maxSize), s.isPromcsMode, pcap.BlockForever)
	if err != nil {
		return err
	}

	return nil
}
