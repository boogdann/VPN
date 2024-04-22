package sniffer

п(
"fmt"
"log/slog"

"github.com/google/gopacket"
"github.com/google/gopacket/pcap"
)

func (s *Sniffer) Start() error {
	s.log.Info("Starting sniffer")
	err := s.listenInterface()
	if err != nil {
		s.log.Error("Error during starting sniffer: ",
			slog.String("error", err.Error()))
		return err
	}

	s.log.Info("Sinffer stopped")
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

	filter := fmt.Sprintf("(tcp and dst pord %s)", s.config.Client.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Error("set interface filter",
			slog.String("error", err.Error()))
		return err
	}

	s.recv = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for {
		select {
		case packet := <-s.recv:
			s.log.Info("get packet")
			s.handler.Handle(packet)
		case packet := <-s.send:
			if err := s.sendMsg(handle, packet); err != nil {
				// TODO: handle error
			}
		case <-s.close:
			return nil
		}
	}
}

func (s *Sniffer) Send(packet gopacket.SerializeBuffer) {
	s.send <- packet
}

func (s *Sniffer) Close() {
	s.log.Info("Stopping sniffer")
	s.close <- struct{}{}
}

func (s *Sniffer) sendMsg(handle *pcap.Handle, packet gopacket.SerializeBuffer) error {
	if err := handle.WritePacketData(packet.Bytes()); err != nil {
		s.log.Error("sending packet", slog.String("error", err.Error()))
		return err
	}

	return nil
}
