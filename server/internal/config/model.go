package config

import "net"

type Config struct {
	InfName     string
	SendInfName string
	Env         string
	Type        string
	Client      ClientConfig
	Server      ServerConfig
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

type NextNodeConfig struct {
	IPv4 net.IP
	IPv6 net.IP
	MAC  net.HardwareAddr
	Port int16
}

type config struct {
	InfName     string         `yaml:"interface_name"`
	SendInfName string         `yaml:"send_interface_name"`
	Env         string         `yaml:"env"`
	Type        string         `yaml:"type"`
	Client      clientConfig   `yaml:"client"`
	Server      serverConfig   `yaml:"server"`
	Next        nextNodeConfig `yaml:"next_node"`
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

type nextNodeConfig struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
	MAC  string `yaml:"mac"`
	Port string `yaml:"port"`
}
