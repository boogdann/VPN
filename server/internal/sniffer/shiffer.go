package sniffer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func (s *Sniffer) Start() {
	s.listenInterface()
}

func (s *Sniffer) listenInterface() error {
	handle, err := pcap.OpenLive(s.name, s.maxSize, s.isPromcsMode, pcap.BlockForever)
	if err != nil {
		return err
	}

	filter := fmt.Sprintf("(tcp and dst pord %s)", s.config.Client.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return err
	}

	s.recv = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for {
		select {
		case packet := <-s.recv:
			go s.handler.Handle(packet)
		case packet := <-s.send:
			send(handle, packet)
		case <-s.close:
			return nil
		}
	}
}

func (s *Sniffer) Send(packet gopacket.SerializeBuffer) {
	s.send <- packet
}

func (s *Sniffer) Recv() chan gopacket.Packet {
	return s.recv
}

func (s *Sniffer) Close() {
	s.close <- struct{}{}
}

func send(handle *pcap.Handle, packet gopacket.SerializeBuffer) error {
	if err := handle.WritePacketData(packet.Bytes()); err != nil {
		return err
	}
	return nil
}
