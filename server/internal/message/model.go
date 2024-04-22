package message

import "log/slog"

type Message struct {
	log *slog.Logger
}

func New(log *slog.Logger) *Message {
	return &Message{
		log: log,
	}
}
