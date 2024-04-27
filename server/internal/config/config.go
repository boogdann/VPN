package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"net"
)

func MustLoad() *Config {
	// TODO: get config path from env + add other types of config
	configPath := "config/config.yaml"
	return MustLoadByPath(configPath)
}

func MustLoadByPath(path string) *Config {
	cfg := new(Config)

	if err := cleanenv.ReadConfig(path, cfg); err != nil {
		panic(err)
	}

	t, _ := getMacAddr()
	cfg.Client.MAC = t[0]
	cfg.Server.MAC = cfg.Client.MAC

	return cfg
}

func getMacAddr() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}
