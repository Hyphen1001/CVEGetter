package utils_test

import (
	"strconv"
	"sync"
	"testing"

	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils"

	"github.com/sirupsen/logrus"
)

func TestConcurrentWriteFile(t *testing.T) {
	wg := sync.WaitGroup{}
	type testStruct struct {
		Index   int    `json:"index"`
		Content string `json:"content"`
	}

	for i := 0; i < 50; i++ {
		wg.Add(common.NumberOne)
		go func(i int) {
			err := utils.ConcurrentWriteFile("file_test.json", testStruct{
				Index:   i,
				Content: "this is index " + strconv.Itoa(i),
			})
			if err != nil {
				logrus.Error(err)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}
