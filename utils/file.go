package utils

import (
	"encoding/json"
	"fmt"
	"github.com/juju/errors"
	"os"
	"sync"

	"edu.buaa.soft/CVEGetter/entity/common"
)

type FileLock struct {
	lock          *sync.Mutex
	fileWritten   int
	resultWritten int
}

const (
	statisticsMod = 100
)

var fileLock *FileLock

func InitFileLock() {
	fileLock = &FileLock{
		lock:          &sync.Mutex{},
		fileWritten:   0,
		resultWritten: 0,
	}
}
func GetfileLockStatistics() (file, result int) {
	return fileLock.fileWritten, fileLock.resultWritten
}

func ConcurrentWriteFile(filename string, content interface{}) error {
	fileLock.lock.Lock()
	defer fileLock.lock.Unlock()
	contentMarshaled, err := json.Marshal(content)
	if err != nil {
		return errors.Trace(err)
	}
	contentBefore, err := os.ReadFile(filename)
	contentAfter := append(contentBefore, contentMarshaled...)
	contentAfter = append(contentAfter, common.SymbolCommaByte)
	contentAfter = append(contentAfter, common.SymbolEnterByte)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, contentAfter, 0777)
	if err != nil {
		return fmt.Errorf("[ConcurrentWriteFile]write file %s error: %w", filename, err)
	}
	if filename == common.BeforeResultPath || filename == common.BeforeExceptionPath {
		fileLock.fileWritten++
		if fileLock.fileWritten%statisticsMod == 0 {
			fmt.Printf("[DeveloperOutput][ConcurrentWriteFile]have written %d before file\n", fileLock.fileWritten)
		}
	}
	if filename == common.AfterResultPath || filename == common.AfterExceptionPath {
		fileLock.resultWritten++
		if fileLock.resultWritten%statisticsMod == 0 {
			fmt.Printf("[DeveloperOutput][ConcurrentWriteFile]have written %d result\n", fileLock.resultWritten)
		}
	}
	return nil
}
