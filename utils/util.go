package utils

import (
	"edu.buaa.soft/CVEGetter/entity/common"
	"os"
)

func IsDev() bool {
	env := os.Getenv(common.CVEGETTERENV)
	return env == "dev"
}
