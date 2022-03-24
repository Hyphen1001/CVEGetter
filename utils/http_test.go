package utils_test

import (
	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/utils"
	"io/ioutil"
	"testing"
)

func TestRequestWithGitToken(t *testing.T) {
	config.InitConfigWithConfPath("../conf/conf.yaml")
	resp, _ := utils.RequestWithGitToken("https://github.com/sylabs/singularity/raw/618c9d56802399adb329c23ea2b70598eaff4a31/cmd/internal/cli/actions_linux.go",
		"", "GET")
	body, _ := ioutil.ReadAll(resp.Body)
	ioutil.WriteFile("actions_linux.go", body, 0777)
}
