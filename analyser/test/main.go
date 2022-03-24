package main

import (
	"fmt"
	"os"

	"edu.buaa.soft/CVEGetter/analyser"
	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"

	"github.com/sirupsen/logrus"
)

func main() {
	//配置初始化
	config.InitConfigWithConfPath(common.ConfPathMain)
	//日志等级初始化
	logrusInit()
	//将data清空
	dataClear()

	meta := &entity.ResultBeforeAnalyse{
		GhsaID: "GHSA-2j6v-xpf3-xvrv",
		CveID:  "CVE-2021-41193",
		CweIDs: []entity.CWE{
			entity.CWE{
				CWEID: "CWE-134",
				Name:  "Use of Externally-Controlled Format String",
			},
		},
		CommitURL: "https://github.com/wireapp/wire-avs/commit/40d373ede795443ae6f2f756e9fb1f4f4ae90bbe",
	}
	analyser.FileAnalyserHandle(meta)
}

func logrusInit() {
	level, err := logrus.ParseLevel(config.LoadConfig().LogLevel)
	if err != nil {
		panic(fmt.Errorf("[logrusInit]parse level failed: %w", err))
	}
	logrus.SetLevel(level)
}

func dataClear() {
	err := os.WriteFile(common.BeforeResultPath, nil, common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	err = os.WriteFile(common.BeforeExceptionPath, nil, common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	err = os.WriteFile(common.AfterResultPath, nil, common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	err = os.WriteFile(common.AfterExceptionPath, nil, common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
}
