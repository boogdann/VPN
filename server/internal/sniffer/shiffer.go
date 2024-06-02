package sniffer

import (
	"fmt"
	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func (s *Sniffer) Start() error {
	s.log.Info("starting sniffer")
	err := s.listenInterface()
	if err != nil {
		s.log.Error("Error during starting sniffer: ",
			slog.String("error", err.Error()))
		return err
	}

	s.log.Info("sniffer stopped")
	return nil
}

func (s *Sniffer) listenInterface() error {
	log := s.log.With(slog.String("op", "Listening"))

	handle, err := pcap.OpenLive(s.name, s.maxSize, s.isPromcsMode, pcap.BlockForever)
	if err != nil {
		log.Error("Open network interface",
			slog.String("error", err.Error()))
		return err
	}

	if s.config.Type == "client" {
		filter := fmt.Sprintf("((tcp or udp) and (src host %s or %s) and src port %d) or (udp and dst port %d)",
			s.config.Client.IPv4, s.config.Client.IPv6, s.config.Client.Port, s.config.Server.Port)

		//filter := fmt.Sprintf("((tcp or udp) and (src host %s or %s) and src port %d) or (udp and src host %s and dst port %d)",
		//	s.config.Client.IPv4, s.config.Client.IPv6, s.config.Client.Port, s.config.Server.IPv4, s.config.Server.Port)

		log.Info("filter", slog.String("filter", filter))
		err := handle.SetBPFFilter(filter)
		if err != nil {
			log.Error("set interface filter",
				slog.String("error", err.Error()))
			return err
		}
	} else {
		filter := fmt.Sprintf("((tcp or udp) and dst port %d) or (udp and src host %s and dst port %d)", s.config.Client.Port, s.config.Server.IPv6, s.config.Client.Port)

		//filter := fmt.Sprintf("(tcp and dst port %d)", s.config.Server.Port)

		log.Info("filter", slog.String("filter", filter))
		err := handle.SetBPFFilter(filter)
		if err != nil {
			log.Error("set interface filter",
				slog.String("error", err.Error()))
			return err
		}
	}

	recv := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for {
		select {
		case packet := <-recv:
			s.log.Info("get packet")
			go s.handler.Handle(packet, s.Send)
		case packet := <-s.send:
			go s.sender.Send(packet)
		case <-s.close:
			return nil
		}
	}
}

func (s *Sniffer) Send(packet []byte) {
	s.send <- packet
}

func (s *Sniffer) Close() {
	s.log.Info("Stopping sniffer")
	s.close <- struct{}{}
}
