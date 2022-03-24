package graphql

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
	"edu.buaa.soft/CVEGetter/utils"

	"github.com/juju/errors"
	"github.com/sirupsen/logrus"
)

type Payload struct {
	Query string `json:"query"`
}

const (
	cweConnectionFirst = 10
)

func GitGraphqlGet(ghsaID string) (ret *entity.GraphQLResp, err error) {
	ret, err = requestGithubGraphQLAPI(ghsaID, cweConnectionFirst)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if ret.Data.SecurityAdvisory.CWEs.TotalCount > cweConnectionFirst {
		return requestGithubGraphQLAPI(ghsaID, ret.Data.SecurityAdvisory.CWEs.TotalCount)
	}
	logrus.Infof("get graphql success for file: %s", ghsaID)
	return
}

func requestGithubGraphQLAPI(ghsaID string, first int) (ret *entity.GraphQLResp, err error) {
	payload := Payload{
		Query: generateQuery(ghsaID, first),
	}
	payloadMarshaled, _ := json.Marshal(payload)

	res, err := utils.RequestWithGitToken(config.LoadConfig().GithubAPIURL,
		string(payloadMarshaled), common.HttpMethodPost)
	defer res.Body.Close()
	if err != nil {
		return nil, errors.Trace(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Trace(err)
	}
	logrus.Infof("get body: %s", body)

	err = json.Unmarshal(body, &ret)
	if err != nil {
		return nil, errors.Trace(err)
	}
	ret.Data.SecurityAdvisory.GhsaID = ghsaID
	return
}

func generateQuery(ghsaID string, first int) string {
	return fmt.Sprint(
		`query { 
	securityAdvisory(ghsaId:"` + ghsaID + `") {
		cwes(first:` + strconv.Itoa(first) + `){
			nodes{
				cweId
				name
			}
			totalCount
		}
		references{
			url
		}
		identifiers{
			type
			value
		}
	} 
}`)
}
