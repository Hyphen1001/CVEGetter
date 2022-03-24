package entity

type GitFile struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Sha         string   `json:"sha"`
	Size        int      `json:"size"`
	Url         string   `json:"url"`
	HtmlUrl     string   `json:"html_url"`
	GitUrl      string   `json:"git_url"`
	DownloadUrl string   `json:"download_url"`
	Type        string   `json:"type"`
	Links       GitLinks `json:"_links"`
}

type GitLinks struct {
	Self string `json:"self"`
	Git  string `json:"git"`
	Html string `json:"html"`
}
