package config

import "github.com/ilyakaznacheev/cleanenv"

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

	return cfg
}
