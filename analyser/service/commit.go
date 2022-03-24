package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils"
)

const (
	getAllCommitURL     = "https://api.github.com/repos/{project}/commits"
	projectTemp         = "{project}"
	paramPerPage        = "per_page"
	paramPage           = "page"
	pageSize            = 2
	paramSHA            = "sha"
	githubDomain        = "https://github.com/"
	urlCommit           = "/commit/"
	getCommitContentURL = "https://api.github.com/repos/{project}/commits/{commit_id}"
	commitIDTemp        = "{commit_id}"
	commitRespLen       = 2
)

type SimpleCommitResp struct {
	SHA string `json:"sha"`
}

type CommitContentResp struct {
	Sha         string         `json:"sha"`
	NodeId      string         `json:"node_id"`
	Url         string         `json:"url"`
	HtmlUrl     string         `json:"html_url"`
	CommentsUrl string         `json:"comments_url"`
	Files       []FileInfoResp `json:"files"`
}

type FileInfoResp struct {
	Sha         string `json:"sha"`
	Filename    string `json:"filename"`
	Status      string `json:"status"`
	Additions   int    `json:"additions"`
	Deletions   int    `json:"deletions"`
	Changes     int    `json:"changes"`
	BlobUrl     string `json:"blob_url"`
	RawUrl      string `json:"raw_url"`
	ContentsUrl string `json:"contents_url"`
	Patch       string `json:"patch"`
}

func GetPatchInfoByCommit(dto *entity.ResultDTO) (*CommitContentResp, error) {
	url := strings.ReplaceAll(getCommitContentURL, projectTemp, dto.Project)
	url = strings.ReplaceAll(url, commitIDTemp, dto.CommitID)
	resp, err := utils.SimpleRequest(url, common.HttpMethodGet)
	defer resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("[GetPatchInfoByCommit]get commit failed: %w", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[GetPatchInfoByCommit]read body failed: %w", err)
	}
	commitContentResp := CommitContentResp{}
	err = json.Unmarshal(body, &commitContentResp)
	if err != nil {
		return nil, fmt.Errorf("[GetPatchInfoByCommit]unmarshal failed: %w", err)
	}
	return &commitContentResp, nil
}

func SetLastCommit(dto *entity.ResultDTO) error {
	url := strings.ReplaceAll(getAllCommitURL, projectTemp, dto.Project)
	resp, err := utils.RequestWithQueryParams(url, common.NilString, common.HttpMethodGet,
		map[string]string{
			paramPerPage: strconv.Itoa(pageSize),
			paramSHA:     dto.CommitID,
		},
	)
	defer resp.Body.Close()
	if err != nil {
		return fmt.Errorf("[SetLastCommit]get commit failed: %w", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("[SetLastCommit]read body failed: %w", err)
	}
	commitsThisPage := []*SimpleCommitResp{}
	err = json.Unmarshal(body, &commitsThisPage)
	if err != nil {
		return fmt.Errorf("[SetLastCommit]unmarshal failed: %w", err)
	}
	if len(commitsThisPage) != commitRespLen {
		return fmt.Errorf("[SetLastCommit]in valid commit resp len: %d", len(commitsThisPage))
	}
	dto.LastCommitID = commitsThisPage[1].SHA
	dto.LastCommitURL = githubDomain + dto.Project + urlCommit + dto.LastCommitID
	return nil
}

//func SetLastCommit(dto *entity.ResultDTO) error {
//	pageNow := 1
//	url := strings.ReplaceAll(getAllCommitURL, projectTemp, dto.Project)
//	for {
//		commitsThisPage, err := getCommits(pageNow, url)
//		if err != nil {
//			return fmt.Errorf("[SetLastCommit]get commits failed: %w, commit is :%s", err, dto.CommitID)
//		}
//		for i, simpleCommitResp := range commitsThisPage {
//			if simpleCommitResp.SHA == dto.CommitID {
//				if i == len(commitsThisPage)-1 {
//					commitsNextPage, err := getCommits(pageNow, url)
//					if err != nil {
//						return fmt.Errorf("[SetLastCommit]get commits failed: %w, commit is :%s", err, dto.CommitID)
//					}
//					dto.LastCommitID = commitsNextPage[0].SHA
//					dto.LastCommitURL = githubDomain + dto.Project + urlCommit + dto.LastCommitID
//				} else {
//					dto.LastCommitID = commitsThisPage[i+1].SHA
//					dto.LastCommitURL = githubDomain + dto.Project + urlCommit + dto.LastCommitID
//				}
//				return nil
//			}
//		}
//		pageNow++
//	}
//}

//func getCommits(pageNow int, url string) ([]*SimpleCommitResp, error) {
//	resp, err := utils.RequestWithQueryParams(url, common.NilString, common.HttpMethodGet,
//		map[string]string{
//			paramPage:    strconv.Itoa(pageNow),
//			paramPerPage: strconv.Itoa(pageSize),
//		},
//	)
//	defer resp.Body.Close()
//	if err != nil {
//		return nil, fmt.Errorf("[getCommits]get commit in page %d failed: %w", pageNow, err)
//	}
//	body, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		return nil, fmt.Errorf("[getCommits]read body failed: %w", err)
//	}
//	commitsThisPage := []*SimpleCommitResp{}
//	err = json.Unmarshal(body, &commitsThisPage)
//	if err != nil {
//		return nil, fmt.Errorf("[getCommits]unmarshal failed: %w", err)
//	}
//	if len(commitsThisPage) == 0 {
//		return nil, fmt.Errorf("[SetLastCommit]no last commit id are found")
//	}
//	return commitsThisPage, nil
//}
