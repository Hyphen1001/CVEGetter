package github_test

import (
	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/utils/github"
	"encoding/json"
	"fmt"
	"testing"
)

func TestGetRepoFiles(t *testing.T) {
	config.InitConfigWithConfPath("../../conf/conf.yaml")
	files, err := github.GetRepoFiles("advisory-database", "github", "/advisories")
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		fileMarshaled, err := json.Marshal(file)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(fileMarshaled))
	}
}
