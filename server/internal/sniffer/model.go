package sniffer

type Sniffer struct {
	name         string
	maxSize      int32
	send         chan []byte
	recv         chan []byte
	isPromcsMode bool
}

func New(name string, size int) *Sniffer {
	return &Sniffer{
		name:         name,
		maxSize:      int32(size),
		isPromcsMode: true,
	}
}
