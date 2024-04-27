package config

import "net"

type Config struct {
	Env    string
	Type   string
	Client ClientConfig
	Server ServerConfig
}

type ClientConfig struct {
	IPv4 net.IP
	IPv6 net.IP
	MAC  net.HardwareAddr
	Port int16
}

type ServerConfig struct {
	IPv4 net.IP
	IPv6 net.IP
	MAC  net.HardwareAddr
	Port int16
}

type config struct {
	Env    string       `yaml:"env"`
	Type   string       `yaml:"type"`
	Client ClientConfig `yaml:"client"`
	Server ServerConfig `yaml:"server"`
}

type clientConfig struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
	MAC  string `yaml:"mac"`
	Port string `yaml:"port"`
}

type serverConfig struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
	MAC  string `yaml:"mac"`
	Port string `yaml:"port"`
}
