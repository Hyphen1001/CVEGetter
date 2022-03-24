package main

import (
	"edu.buaa.soft/CVEGetter/analyser"
	"edu.buaa.soft/CVEGetter/handler"
	"edu.buaa.soft/CVEGetter/utils"
	"edu.buaa.soft/CVEGetter/utils/pool"
	"fmt"
	"os"

	"edu.buaa.soft/CVEGetter/config"
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
	//文件IO初始化
	utils.InitFileLock()
	//pool初始化
	pool.InitTokenPool()
	pool.InitGoRoutineLock()

	fmt.Println("[DeveloperOutput][CVEGetter]服务初始化成功！")

	//主服务启动
	isAnalyserTest := func() bool {
		env := os.Getenv("MAIN_ROOT")
		return env == "analyser_dev"
	}()
	if isAnalyserTest {
		analyser.TestHandler()
	} else {
		handler.Handle()
	}
	file, result := utils.GetfileLockStatistics()
	fmt.Printf("[DeveloperOutput][CVEGetter]处理完成，共处理文件：%d 个，获得结果： %d 条\n", file, result)
}

func logrusInit() {
	level, err := logrus.ParseLevel(config.LoadConfig().LogLevel)
	if err != nil {
		panic(fmt.Errorf("[logrusInit]parse level failed: %w", err))
	}
	logrus.SetLevel(level)
	fmt.Println("[DeveloperOutput][logrusInit]日志初始化成功！")
}

func dataClear() {
	err := os.WriteFile(common.BeforeResultPath, []byte(""), common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	err = os.WriteFile(common.BeforeExceptionPath, []byte(""), common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	err = os.WriteFile(common.AfterResultPath, []byte(""), common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	err = os.WriteFile(common.AfterExceptionPath, []byte(""), common.FilePerm)
	if err != nil {
		panic(fmt.Errorf("clear before resule failed: %w", err))
	}
	fmt.Println("[DeveloperOutput][dataClear]数据初始化成功！")
}
