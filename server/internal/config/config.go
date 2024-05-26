package config

import (
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"net"
	"strconv"
)

func MustLoad() *Config {
	// TODO: get config path from env + add other types of config
	configPath := "config/config.yaml"
	return MustLoadByPath(configPath)
}

func MustLoadByPath(path string) *Config {
	rawCfg := new(config)

	if err := cleanenv.ReadConfig(path, rawCfg); err != nil {
		panic(err)
	}

	cfg, err := setConfig(rawCfg)
	if err != nil {
		panic(err)
	}

	return cfg
}

func getMacAddr() ([]net.HardwareAddr, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var as []net.HardwareAddr
	for _, ifa := range ifas {
		a := ifa.HardwareAddr
		if a.String() != "" {
			as = append(as, a)
		}
	}
	return as, nil
}

func setConfig(rawCfg *config) (*Config, error) {
	cfg := new(Config)
	cfg.Env = rawCfg.Env
	cfg.Type = rawCfg.Type

	cfg.Client.IPv4 = net.ParseIP(rawCfg.Client.IPv4)
	if cfg.Client.IPv4 == nil {
		cfg.Client.IPv4 = net.ParseIP("0.0.0.0")
	}

	cfg.Client.IPv6 = net.ParseIP(rawCfg.Client.IPv6)
	if cfg.Client.IPv6 == nil {
		cfg.Client.IPv6 = net.ParseIP("::")
	}

	var err error
	cfg.Client.MAC, err = net.ParseMAC(rawCfg.Client.MAC)
	if err != nil {
		var macs []net.HardwareAddr
		macs, err = getMacAddr()
		if err != nil {
			return nil, err
		}
		cfg.Client.MAC = macs[0]
	}

	val, err := strconv.ParseInt(rawCfg.Client.Port, 10, 16)
	cfg.Client.Port = int16(val)

	cfg.Server.IPv4 = net.ParseIP(rawCfg.Server.IPv4)
	if cfg.Server.IPv4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address %s", rawCfg.Server.IPv4)
	}

	cfg.Server.IPv6 = net.ParseIP(rawCfg.Server.IPv6)
	if cfg.Server.IPv6 == nil {
		return nil, fmt.Errorf("invalid IPv6 address %s", rawCfg.Server.IPv6)
	}

	cfg.Server.MAC, err = net.ParseMAC(rawCfg.Server.MAC)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %s", rawCfg.Server.MAC)
	}

	val, err = strconv.ParseInt(rawCfg.Server.Port, 10, 16)
	cfg.Server.Port = int16(val)

	//cfg.Next.IPv4 = net.ParseIP(rawCfg.Next.IPv4)
	//if cfg.Next.IPv4 == nil {
	//	return nil, fmt.Errorf("invalid IPv4 address %s", rawCfg.Next.IPv4)
	//}
	//
	//cfg.Next.IPv6 = net.ParseIP(rawCfg.Next.IPv6)
	//if cfg.Next.IPv6 == nil {
	//	return nil, fmt.Errorf("invalid IPv6 address %s", rawCfg.Next.IPv6)
	//}
	//
	//cfg.Next.MAC, err = net.ParseMAC(rawCfg.Next.MAC)
	//if err != nil {
	//	return nil, fmt.Errorf("invalid MAC address %s", rawCfg.Next.MAC)
	//}
	//
	//val, err = strconv.ParseInt(rawCfg.Next.Port, 10, 16)
	//cfg.Next.Port = int16(val)

	cfg.InfName = rawCfg.InfName

	cfg.SendInfName = rawCfg.SendInfName

	return cfg, nil
}
