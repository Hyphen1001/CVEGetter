package main

import (
	"encoding/json"
	"fmt"
	"os"

	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils/github"

	"github.com/sirupsen/logrus"
)

const (
	TimesLimit = 50

	dbUser   = "github"
	dbRepo   = "advisory-database"
	typeFile = "file"

	fileRootPath = "/advisories/github-reviewed"
)

var Times = 0

func main() {
	config.InitConfigWithConfPath("conf/conf.yaml")
	WriteGhsaIdFromGit()
}

func WriteGhsaIdFromGit() {
	rootFiles, err := github.GetRepoFiles(dbRepo, dbUser, fileRootPath)
	if err != nil {
		logrus.Error(fmt.Errorf("[HandleAllGhsaIdFromGit]get repo files failed: %w", err))
	}
	logrus.Info("get root file success")
	files := []*entity.GitFile{}
	for _, file := range rootFiles {
		files = append(files, handleChildFilesFromGit(file, fileRootPath+common.SymbolSlashString+file.Name)...)
	}
	filesMarshaled, err := json.Marshal(files)
	os.WriteFile(common.GhsaIDResultPath, filesMarshaled, 0777)
}

func handleChildFilesFromGit(file *entity.GitFile, path string) []*entity.GitFile {
	if Times >= TimesLimit {
		return nil
	}
	logrus.Info("handle file ", file.Name)
	if file.Type == typeFile {
		Times++
		return []*entity.GitFile{file}
	}
	childFiles, err := github.GetRepoFiles(dbRepo, dbUser, path)
	if err != nil {
		logrus.Error(fmt.Errorf("[HandleAllGhsaIdFromGit]get repo files failed: %w", err))
	}
	files := []*entity.GitFile{}
	for _, file := range childFiles {
		files = append(files, handleChildFilesFromGit(file, path+common.SymbolSlashString+file.Name)...)
	}
	return files
}
