package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Target struct {
	Name      string `yaml:"name"`
	MatchComm string `yaml:"match_comm"`
}

type Export struct {
	ListenAddr string `yaml:"listen_addr"`
}

type Otel struct {
	Endpoint string `yaml:"endpoint"`
	Insecure bool   `yaml:"insecure"`
}

type Config struct {
	Interfaces []string `yaml:"interfaces"`
	Targets    []Target `yaml:"targets"`
	Export     Export   `yaml:"export"`
	Otel       Otel     `yaml:"otel"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	if c.Export.ListenAddr == "" {
		c.Export.ListenAddr = ":9102"
	}
	return c, nil
}
