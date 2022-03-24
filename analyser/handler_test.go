package analyser_test

import (
	"testing"

	"edu.buaa.soft/CVEGetter/analyser"
	"edu.buaa.soft/CVEGetter/entity"
)

func TestFileAnalyserHandle(t *testing.T) {

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
