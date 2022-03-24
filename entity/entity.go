package entity

type GraphQLResp struct {
	Data RespData `json:"data"`
}

type RespData struct {
	SecurityAdvisory SecurityAdvisoryData `json:"securityAdvisory"`
}

type SecurityAdvisoryData struct {
	GhsaID      string                       `json:"ghsaId"`
	Identifiers []SecurityAdvisoryIdentifier `json:"identifiers"`
	References  []SecurityAdvisoryReference  `json:"references"`
	CWEs        CWEConnection                `json:"cwes"`
}

type SecurityAdvisoryReference struct {
	URL string `json:"url"`
}

type CWEConnection struct {
	Nodes      []CWE `json:"nodes"`
	TotalCount int   `json:"totalCount"`
}

type SecurityAdvisoryIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ResultBeforeAnalyse struct {
	GhsaID    string `json:"ghsaId"`
	CveID     string `json:"cve_id"`
	CweIDs    []CWE  `json:"cwe_id"`
	CommitURL string `json:"commit_url"`
}

type ResultDTO struct {
	Project       string `json:"project"`
	GhsaID        string `json:"ghsaId"`
	CveID         string `json:"cve_id"`
	CweIDs        []CWE  `json:"cwe_id"`
	CommitURL     string `json:"commit_url"`
	CommitID      string `json:"commit_id"`
	LastCommitURL string `json:"last_commit_url"`
	LastCommitID  string `json:"last_commit_id"`
	TypeStruct    struct {
		A int    `json:"a"`
		B string `json:"b"`
	} `json:"type_struct"`
}

func (r *ResultDTO) GetResultAfterAnalyseFromResultDTO() *ResultAfterAnalyse {
	return &ResultAfterAnalyse{
		Project:   r.Project,
		GhsaID:    r.GhsaID,
		CveID:     r.CveID,
		CweIDs:    r.CweIDs,
		CommitURL: r.CommitURL,
	}
}

type ResultAfterAnalyse struct {
	Project        string `json:"project"`
	FileName       string `json:"file_name"`
	Target         string `json:"target"`
	GhsaID         string `json:"ghsaId"`
	CveID          string `json:"cve_id"`
	CweIDs         []CWE  `json:"cwe_id"`
	CommitURL      string `json:"commit_url"`
	TreeSitterType string `json:"tree_sitter_type"`
	Language       string `json:"language"`
	Content        string `json:"func"`
}

type CWE struct {
	CWEID string `json:"cweId"`
	Name  string `json:"name"`
}

type FuncContentArray struct {
	Bound          [2]uint64
	TreeSitterType string
}
