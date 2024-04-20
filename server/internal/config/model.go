package config

type Config struct {
    client ClientConfig
    server ServerConfig
}

type ClientConfig struct {
    IPv4 string
    IPv6 string
    MAC  string
    Port string
}

type ServerConfig struct {
    IPv4 string
    IPv6 string
    MAC  string
    Port string
}
