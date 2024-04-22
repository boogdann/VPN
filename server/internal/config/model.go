package config

type Config struct {
	Env    string       `yaml:"env"`
	Type   string       `yaml:"type"`
	Client ClientConfig `yaml:"client"`
	Server ServerConfig `yaml:"server"`
}

type ClientConfig struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
	MAC  string `yaml:"mac"`
	Port string `yaml:"port"`
}

type ServerConfig struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
	MAC  string `yaml:"mac"`
	Port string `yaml:"port"`
}
