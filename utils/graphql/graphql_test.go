package graphql_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/utils/graphql"
)

func TestGraphqlGet(t *testing.T) {
	config.InitConfigWithConfPath("../../conf/conf.yaml")
	graphQLResp, err := graphql.GitGraphqlGet("GHSA-rjmq-6v55-4rjv")
	if err != nil {
		panic(fmt.Errorf("graphqlGet GHSA-rjmq-6v55-4rjv fialed with error: %w", err))
	}
	graphQLRespMarshaled, err := json.Marshal(graphQLResp)
	if err != nil {
		panic(fmt.Errorf("marshal fialed with error: %w", err))
	}
	fmt.Printf(string(graphQLRespMarshaled))
}
