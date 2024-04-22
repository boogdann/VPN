package message

import (
	"fmt"

	"github.com/google/gopacket"
)

func (m *Message) Handle(p gopacket.Packet) {
	fmt.Println(p)
}
