package service

import (
	"edu.buaa.soft/CVEGetter/config"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/python"
)

import (
	"fmt"
	"strings"
	"unicode"

	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils"
	"edu.buaa.soft/CVEGetter/utils/github"
	"edu.buaa.soft/CVEGetter/utils/treesitter"

	"github.com/sirupsen/logrus"
	sitter "github.com/smacker/go-tree-sitter"
)

const (
	getFileURl   = "https://github.com/{project}/raw/{commit_id}/{file_name}"
	fileNameTemp = "{file_name}"
	targetOld    = "0"
	targetNew    = "1"
)

func HandlePatchInfo(patchInfo *CommitContentResp, dto *entity.ResultDTO) {
	urlProject := strings.ReplaceAll(getFileURl, projectTemp, dto.Project)
	urlOldCommit := strings.ReplaceAll(urlProject, commitIDTemp, dto.LastCommitID)
	urlNewCommit := strings.ReplaceAll(urlProject, commitIDTemp, dto.CommitID)
	for _, file := range patchInfo.Files {
		language, suffix, err := getLanguageType(file.Filename)
		if err != nil {
			logrus.Infof(fmt.Sprintf("[HandlePatchInfo]get language type of %s failed: %s", file.Filename, err.Error()), dto)
			continue
		}
		urlOld := strings.ReplaceAll(urlOldCommit, fileNameTemp, file.Filename)
		urlNew := strings.ReplaceAll(urlNewCommit, fileNameTemp, file.Filename)
		codeNew, codeOld, err := getFiles(urlNew, urlOld)
		if err != nil {
			HandleAfterException(fmt.Errorf("[HandlePatchInfo]get file of %s failed: %w", dto.GhsaID, err), dto)
			return
		}
		patchNew, patchOld := HandlePatch([]byte(file.Patch))
		if err != nil {
			HandleAfterException(fmt.Errorf("[HandlePatchInfo]get patch of %s failed: %w", file.Filename, err), dto)
			return
		}
		parserNew := treesitter.NewSitterParser(codeNew, language, suffix)
		resultNew := []*entity.ResultAfterAnalyse{}
		for _, item := range patchNew {
			contents := parserNew.ParseLineToFunc(item[0], item[1])
			for _, contentItem := range contents {
				result := dto.GetResultAfterAnalyseFromResultDTO()
				result.Content = contentItem.Contents
				result.TreeSitterType = contentItem.TreeSitterType
				result.Target = targetNew
				result.FileName = file.Filename
				result.Language = suffix
				resultNew = append(resultNew, result)
				//writeFileErr := utils.ConcurrentWriteFile(common.AfterResultPath, result)
				//if writeFileErr != nil {
				//	logrus.Error(fmt.Errorf("[HandlePatchInfo]write file failed: %w", err))
				//}
			}
		}
		parserOld := treesitter.NewSitterParser(codeOld, language, suffix)
		resultOld := []*entity.ResultAfterAnalyse{}
		for _, item := range patchOld {
			contents := parserOld.ParseLineToFunc(item[0], item[1])
			for _, contentItem := range contents {
				result := dto.GetResultAfterAnalyseFromResultDTO()
				result.Content = contentItem.Contents
				result.TreeSitterType = contentItem.TreeSitterType
				result.Target = targetOld
				result.FileName = file.Filename
				result.Language = suffix
				resultOld = append(resultOld, result)
				//writeFileErr := utils.ConcurrentWriteFile(common.AfterResultPath, result)
				//if writeFileErr != nil {
				//	logrus.Error(fmt.Errorf("[HandlePatchInfo]write file failed: %w", err))
				//}
			}
		}
		resultOldChecked, resultNewChecked := resultCheck(resultOld, resultNew)
		for _, result := range resultNewChecked {
			writeFileErr := utils.ConcurrentWriteFile(common.AfterResultPath, result)
			if writeFileErr != nil {
				logrus.Error(fmt.Errorf("[HandlePatchInfo]write file failed: %w", err))
			}
		}
		for _, result := range resultOldChecked {
			writeFileErr := utils.ConcurrentWriteFile(common.AfterResultPath, result)
			if writeFileErr != nil {
				logrus.Error(fmt.Errorf("[HandlePatchInfo]write file failed: %w", err))
			}
		}
	}
}

func resultCheck(old, new []*entity.ResultAfterAnalyse) (retOld, retNew []*entity.ResultAfterAnalyse) {
	for _, resultOld := range old {
		isDuplicate := false
		for _, resultNew := range new {
			if resultNew.TreeSitterType == resultOld.TreeSitterType &&
				resultNew.Content == resultOld.Content {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			retOld = append(retOld, resultOld)
		}
	}
	for _, resultNew := range new {
		isDuplicate := false
		for _, resultOld := range old {
			if resultNew.TreeSitterType == resultOld.TreeSitterType &&
				resultNew.Content == resultOld.Content {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			retNew = append(retOld, resultNew)
		}
	}
	return
}

func HandleAfterException(err error, resp *entity.ResultDTO) {
	logrus.Error(err)
	writeFileErr := utils.ConcurrentWriteFile(common.AfterExceptionPath, resp)
	if writeFileErr != nil {
		logrus.Error(fmt.Errorf("[HandleAfterException]write file failed: %w", writeFileErr))
	}
}

func getFiles(urlNew, urlOld string) (codeNew, codeOld []byte, err error) {
	codeNew, err = github.GetFileCode(urlNew)
	if err != nil {
		return nil, nil, fmt.Errorf("[getFiles]get file new failed: %w", err)
	}
	codeOld, err = github.GetFileCode(urlOld)
	if err != nil {
		return nil, nil, fmt.Errorf("[getFiles]get file old failed: %w", err)
	}
	return
}

func HandlePatch(patch []byte) (patchNew, patchOld [][2]int) {
	isFirst := true
	for i := 0; i < len(patch); i++ {
		if patch[i] == '@' && i < len(patch)-1 && patch[i+1] == '@' {
			if !isFirst {
				isFirst = true
				continue
			}
			j, lineOld, lineNew := i+2, [2]int{0, 0}, [2]int{0, 0}
			for patch[j] == ' ' {
				j++
			}
			if patch[j] == '-' {
				j++
				lineStart, lineAdd, newStart := readNumber(patch, j)
				if lineStart != 0 {
					lineOld[0], lineOld[1], j = lineStart, lineStart+lineAdd-1, newStart
					patchOld = append(patchOld, lineOld)
				}
			}
			for patch[j] == ' ' || patch[j] == ',' {
				j++
			}
			if patch[j] == '+' {
				j++
				lineStart, lineAdd, newStart := readNumber(patch, j)
				if lineStart != 0 {
					lineNew[0], lineNew[1], j = lineStart, lineStart+lineAdd-1, newStart
					patchNew = append(patchNew, lineNew)
				}
			}
			i = j
			isFirst = false
		}
	}
	return
}

func readNumber(input []byte, start int) (lineStart, lineAdd, newStart int) {
	i, lineStart, lineAdd := start, 0, 0
	for i < len(input) && input[i] == ' ' {
		i++
	}
	for unicode.IsDigit(rune(input[i])) {
		lineStart = lineStart*10 + int(input[i]-'0')
		i++
	}
	for i < len(input) && input[i] == ' ' || input[i] == ',' {
		i++
	}
	for i < len(input) && unicode.IsDigit(rune(input[i])) {
		lineAdd = lineAdd*10 + int(input[i]-'0')
		i++
	}
	newStart = i
	return
}

func getLanguageType(fileName string) (*sitter.Language, string, error) {
	fileNameSplit := strings.Split(fileName, ".")
	suffix := fileNameSplit[len(fileNameSplit)-1]
	if !checkLanguageIsAim(suffix) {
		return nil, common.NilString, fmt.Errorf("[getLanguageType]unsupported language: %s", suffix)
	}
	switch suffix {
	case "java":
		return java.GetLanguage(), suffix, nil
	case "c":
		return c.GetLanguage(), suffix, nil
	case "cpp":
		return cpp.GetLanguage(), suffix, nil
	case "py":
		return python.GetLanguage(), suffix, nil
	case "go":
		return golang.GetLanguage(), suffix, nil
	default:
		logrus.Errorf("[getLanguageType]unexpected error happened: %s is not in config but checkLanguageIsAim returns true", suffix)
		return nil, common.NilString, fmt.Errorf("[getLanguageType]illegal suffix: %s", suffix)
	}
}

func checkLanguageIsAim(suffix string) bool {
	result, ok := config.LoadConfig().AimLanguagesMap[suffix]
	if !ok {
		return false
	}
	return result
}
