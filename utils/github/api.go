package github

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils"
)

const (
	githubOpenAPIURL = "https://api.github.com/"
	getRepoRootURL   = "repos/{user}/{repo}/contents"
	userTemp         = "{user}"
	repoTemp         = "{repo}"
)

func GetRepoFiles(repo, user, path string) ([]*entity.GitFile, error) {
	url := githubOpenAPIURL + strings.ReplaceAll(
		strings.ReplaceAll(getRepoRootURL, userTemp, user), repoTemp, repo) + path
	res, err := utils.RequestWithGitAuth(url, "", common.HttpMethodGet)
	defer res.Body.Close()
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	files := []*entity.GitFile{}
	err = json.Unmarshal(body, &files)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func GetFileCode(url string) ([]byte, error) {
	resp, err := utils.SimpleRequest(url, common.HttpMethodGet)
	if err != nil {
		return nil, fmt.Errorf("[GetFileCode]get file from git failed: %w", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[GetFileCode]read file from resp failed: %w", err)
	}
	return body, nil
}
