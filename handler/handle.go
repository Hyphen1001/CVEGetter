package handler

import (
	"edu.buaa.soft/CVEGetter/utils"
	"edu.buaa.soft/CVEGetter/utils/pool"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/getter"
	"edu.buaa.soft/CVEGetter/utils/github"

	"github.com/sirupsen/logrus"
)

const (
	dbUser       = "github"
	dbRepo       = "advisory-database"
	fileRootPath = "/advisories/github-reviewed"
	typeFile     = "file"
)

var (
	wg = sync.WaitGroup{}
)

func Handle() {
	if utils.IsDev() {
		HandleAllGhsaIdFromLocal()
	} else {
		HandleAllGhsaIdFromGit()
	}
	wg.Wait()
}

func HandleAllGhsaIdFromLocal() {
	buffer, err := ioutil.ReadFile(common.GhsaIDResultPath)
	if err != nil {
		panic(err)
	}
	files := []*entity.GitFile{}
	err = json.Unmarshal(buffer, &files)
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		wg.Add(common.NumberOne)
		go func(file *entity.GitFile) {
			getter.FileGetterHandler(file, &wg)
			wg.Done()
		}(file)
	}
}

func HandleAllGhsaIdFromGit() {
	rootFiles, err := github.GetRepoFiles(dbRepo, dbUser, fileRootPath)
	if err != nil {
		logrus.Error(fmt.Errorf("[HandleAllGhsaIdFromGit]get repo files failed: %w", err))
	}
	logrus.Info("get root file success")
	for i := len(rootFiles) - 1; i >= 0; i-- {
		handleChildFilesFromGit(rootFiles[i], fileRootPath+common.SymbolSlashString+rootFiles[i].Name)
	}
}

func handleChildFilesFromGit(file *entity.GitFile, path string) {
	logrus.Info("handle file ", file.Name)
	if file.Type == typeFile {
		wg.Add(common.NumberOne)
		go func(file *entity.GitFile) {
			lock := pool.GetGoRoutineLock()
			lock.Lock()
			for i := 0; i < 3; i++ {
				err := getter.FileGetterHandler(file, &wg)
				if err != nil && err.Error() == getter.ErrPanicHappen {
					time.Sleep(5 * time.Second)
					continue
				}
				break
			}
			lock.Unlock()
			wg.Done()
		}(file)
		return
	}
	childFiles, err := github.GetRepoFiles(dbRepo, dbUser, path)
	if err != nil {
		logrus.Error(fmt.Errorf("[HandleAllGhsaIdFromGit]get repo files failed: %w", err))
	}
	for _, file := range childFiles {
		handleChildFilesFromGit(file, path+common.SymbolSlashString+file.Name)
	}
}
