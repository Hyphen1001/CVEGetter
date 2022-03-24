package config

import (
	"fmt"
	"gopkg.in/yaml.v2"

	"io/ioutil"
)

type Config struct {
	LogLevel string `yaml:"LogLevel"`

	GoRoutineLockPoolSize int `yaml:"GoRoutineLockPoolSize"`

	AimLanguages    []string `yaml:"AimLanguages"`
	AimLanguagesMap map[string]bool

	GithubTokens   []string `yaml:"GithubTokens"`
	GithubAPIURL   string   `yaml:"GithubAPIURL"`
	GithubUsername string   `yaml:"GithubUsername"`
	GithubPassword string   `yaml:"GithubPassword"`
}

var config = Config{}

func InitConfigWithConfPath(path string) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("init config failed, err is: %w", err))
	}
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		panic(fmt.Errorf("unmarshal config failed, err is: %w", err))
	}
	for _, language := range config.AimLanguages {
		config.AimLanguagesMap[language] = true
	}
}

func LoadConfig() *Config {
	return &config
}
