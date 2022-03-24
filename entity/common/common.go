package common

import "os"

const (
	ConfPathMain        = "conf/conf.yaml"
	GhsaIDResultPath    = "data/ghsaid/ghsaid.json"
	BeforeExceptionPath = "data/before_analyse/exception.json"
	BeforeResultPath    = "data/before_analyse/result.json"
	AfterExceptionPath  = "data/after_analyse/exception.json"
	AfterResultPath     = "data/after_analyse/result.json"

	NumberOne             = 1
	FilePerm  os.FileMode = 0777

	SymbolSlashString = "/"
	SymbolEnterByte   = '\n'
	SymbolCommaByte   = ','
	NilString         = ""

	HttpMethodPost = "POST"
	HttpMethodGet  = "GET"

	CVEGETTERENV = "CVE_GETTER_ENV"
	TypeCVE      = "CVE"
)
