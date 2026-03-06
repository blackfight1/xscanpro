package model

type CrawlResult struct {
	URLs   []string
	JSURLs []string
}

type JSDiscovery struct {
	Endpoints     []string
	Params        []string
	RelatedParams map[string][]string
}

type ScanTarget struct {
	URL    string
	Params []string
}

type Finding struct {
	Method          string `json:"method"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	InjectedValue   string `json:"injected_value"`
	Context         string `json:"context"`
	ReflectedLines  []int  `json:"reflected_lines"`
	Indicator       string `json:"indicator"`
	SuggestedAction string `json:"suggested_action"`
}

type Report struct {
	TotalTargets  int       `json:"total_targets"`
	TotalFindings int       `json:"total_findings"`
	Findings      []Finding `json:"findings"`
}
