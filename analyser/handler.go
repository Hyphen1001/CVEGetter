package analyser

import (
	"fmt"
	"strings"

	"edu.buaa.soft/CVEGetter/analyser/service"
	"edu.buaa.soft/CVEGetter/entity"
	"edu.buaa.soft/CVEGetter/entity/common"
)

func FileAnalyserHandle(metaData *entity.ResultBeforeAnalyse) {
	resultDTO, err := resultDTOGetter(metaData)
	if err != nil {
		service.HandleAfterException(fmt.Errorf("[FileAnalyserHandle]get result dto of %s failed: %w", metaData.GhsaID, err), resultDTO)
		return
	}
	//获取本次commit的patch
	patchInfo, err := service.GetPatchInfoByCommit(resultDTO)
	if err != nil {
		service.HandleAfterException(fmt.Errorf("[FileAnalyserHandle]get patch info of %s failed: %w", metaData.GhsaID, err), resultDTO)
		return
	}
	service.HandlePatchInfo(patchInfo, resultDTO)
}

func resultDTOGetter(metaData *entity.ResultBeforeAnalyse) (*entity.ResultDTO, error) {
	resultDTO := entity.ResultDTO{
		GhsaID:    metaData.GhsaID,
		CveID:     metaData.CveID,
		CweIDs:    metaData.CweIDs,
		CommitURL: metaData.CommitURL,
	}
	splitURL := strings.Split(resultDTO.CommitURL, "/")
	resultDTO.Project = splitURL[3] + common.SymbolSlashString + splitURL[4]
	resultDTO.CommitID = splitURL[6]
	//获取上一次commit
	err := service.SetLastCommit(&resultDTO)
	if err != nil {
		return nil, fmt.Errorf("[resultDTOGetter]set last commit failed: %w", err)
	}
	return &resultDTO, nil
}

func TestHandler() {
	meta := &entity.ResultBeforeAnalyse{
		GhsaID: "GHSA-2j6v-xpf3-xvrv",
		CveID:  "CVE-2021-41193",
		CweIDs: []entity.CWE{
			{
				CWEID: "CWE-134",
				Name:  "Use of Externally-Controlled Format String",
			},
		},
		CommitURL: "https://github.com/wireapp/wire-avs/commit/40d373ede795443ae6f2f756e9fb1f4f4ae90bbe",
	}
	FileAnalyserHandle(meta)
	//logrus.Error("start second")
	//meta = &entity.ResultBeforeAnalyse{
	//	GhsaID: "GHSA-38r5-34mr-mvm7",
	//	CveID:  "CVE-2020-29662",
	//	CweIDs: []entity.CWE{
	//		{
	//			CWEID: "CWE-287",
	//			Name:  "Improper Authentication",
	//		},
	//	},
	//	CommitURL: "https://github.com/goharbor/harbor/commit/3481722f140e1fdf6e6d290b0cd5c86e509feed4",
	//}
	//FileAnalyserHandle(meta)
}
