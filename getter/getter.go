package getter

import (
	"edu.buaa.soft/CVEGetter/analyser"
	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils"
	"edu.buaa.soft/CVEGetter/utils/graphql"
	"fmt"
	"github.com/juju/errors"
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

const (
	ErrPanicHappen = "panic happens"
)

var (
	commitURLRegex = "^https://github.com/[^/]*/[^/]*/commit/[0-9a-f]{40}$"
)

func FileGetterHandler(file *entity.GitFile, wg *sync.WaitGroup) (err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.New(ErrPanicHappen)
			return
		}
	}()
	result := entity.ResultBeforeAnalyse{}
	graphqlResp, err := graphql.GitGraphqlGet(strings.Split(file.Name, ".")[0])
	if err != nil {
		logrus.Error(fmt.Errorf("[FileGetterHandler]git graph get failed: %w", err))
	}

	result.GhsaID = graphqlResp.Data.SecurityAdvisory.GhsaID
	result.CveID, err = getCveIDFromResp(graphqlResp)
	if err != nil {
		handleBeforeException(fmt.Errorf("[FileGetterHandler]get cve id failed: %w", err), graphqlResp)
		return nil
	}

	result.CweIDs = graphqlResp.Data.SecurityAdvisory.CWEs.Nodes
	if len(result.CweIDs) == 0 {
		logrus.Info("[FileGetterHandler]cwe id is null")
	}

	result.CommitURL, err = getCommitURLFromResp(graphqlResp)
	if err != nil {
		handleBeforeException(fmt.Errorf("[FileGetterHandler]get commit url failed: %w", err), graphqlResp)
		return nil
	}

	wg.Add(common.NumberOne)
	go func(result *entity.ResultBeforeAnalyse) {
		err := utils.ConcurrentWriteFile(common.BeforeResultPath, result)
		if err != nil {
			logrus.Error(fmt.Errorf("[FileGetterHandler]write file failed: %w", err))
		}
		wg.Done()
	}(&result)

	analyser.FileAnalyserHandle(&result)
	return nil
}

func handleBeforeException(err error, resp *entity.GraphQLResp) {
	logrus.Error(err)
	writeFileErr := utils.ConcurrentWriteFile(common.BeforeExceptionPath, resp)
	if writeFileErr != nil {
		logrus.Error(fmt.Errorf("[FileGetterHandler]write file failed: %w", writeFileErr))
	}
}

func getCveIDFromResp(resp *entity.GraphQLResp) (string, error) {
	for _, identifier := range resp.Data.SecurityAdvisory.Identifiers {
		if identifier.Type == common.TypeCVE {
			return identifier.Value, nil
		}
	}
	return "", fmt.Errorf("[getCveIDFromResp]no cve id")
}

func getCommitURLFromResp(resp *entity.GraphQLResp) (string, error) {
	for _, reference := range resp.Data.SecurityAdvisory.References {
		ok, err := regexp.Match(commitURLRegex, []byte(reference.URL))
		if err != nil {
			logrus.Error(fmt.Errorf("[getCommitURLFromResp]regex match failed: %w", err))
		}
		if ok {
			return reference.URL, nil
		}
	}
	return "", fmt.Errorf("[getCommitURLFromResp]no commit url for %s", resp.Data.SecurityAdvisory.GhsaID)
}
