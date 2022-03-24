package config_test

import (
	"edu.buaa.soft/CVEGetter/config"
	"encoding/json"
	"fmt"
	"testing"
)

func TestInitConfigWithConfPath(t *testing.T) {
	config.InitConfigWithConfPath("../conf/conf.yaml")
	conf, err := json.Marshal(config.LoadConfig())
	if err != nil {
		panic(err)
	}
	fmt.Println(string(conf))
}
