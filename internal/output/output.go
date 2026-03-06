package output

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"xscanpro/internal/model"
	"xscanpro/internal/util"
)

type findingView struct {
	URL         string `json:"url"`
	Param       string `json:"param"`
	Payload     string `json:"payload"`
	Context     string `json:"context"`
	Evidence    string `json:"evidence"`
	Occurrences int    `json:"occurrences"`
}

type reportView struct {
	TotalTargets  int           `json:"total_targets"`
	TotalFindings int           `json:"total_findings"`
	RawFindings   int           `json:"raw_findings"`
	Findings      []findingView `json:"findings"`
}

func WritePipelineArtifacts(outDir string, urls, jsURLs, endpoints, params []string, report model.Report) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(outDir, "urls.txt"), urls); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(outDir, "js_urls.txt"), jsURLs); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(outDir, "endpoints.txt"), endpoints); err != nil {
		return err
	}
	if err := util.WriteLines(filepath.Join(outDir, "params.txt"), params); err != nil {
		return err
	}

	viewFindings := dedupeForReport(report.Findings)
	view := reportView{
		TotalTargets:  report.TotalTargets,
		TotalFindings: len(viewFindings),
		RawFindings:   report.TotalFindings,
		Findings:      viewFindings,
	}

	b, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "findings.json"), b, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "xss_report.md"), []byte(renderMarkdownReport(view)), 0644)
}

func renderMarkdownReport(r reportView) string {
	var sb strings.Builder
	sb.WriteString("# XSS Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("- Total Targets: %d\n", r.TotalTargets))
	sb.WriteString(fmt.Sprintf("- Total Findings: %d\n", r.TotalFindings))
	sb.WriteString(fmt.Sprintf("- Raw Findings: %d\n\n", r.RawFindings))

	if len(r.Findings) == 0 {
		sb.WriteString("## Findings\n\nNo findings.\n")
		return sb.String()
	}

	ordered := make([]findingView, len(r.Findings))
	copy(ordered, r.Findings)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].URL != ordered[j].URL {
			return ordered[i].URL < ordered[j].URL
		}
		if ordered[i].Param != ordered[j].Param {
			return ordered[i].Param < ordered[j].Param
		}
		return ordered[i].Context < ordered[j].Context
	})

	sb.WriteString("## Findings\n\n")
	for i, f := range ordered {
		sb.WriteString(fmt.Sprintf("### %d. Param: %s\n\n", i+1, f.Param))
		sb.WriteString(fmt.Sprintf("- Vulnerable URL: `%s`\n", f.URL))
		sb.WriteString(fmt.Sprintf("- Payload: `%s`\n", f.Payload))
		sb.WriteString(fmt.Sprintf("- Context: `%s`\n", f.Context))
		sb.WriteString(fmt.Sprintf("- Evidence: %s\n", f.Evidence))
		sb.WriteString(fmt.Sprintf("- Occurrences: %d\n", f.Occurrences))
		sb.WriteString(fmt.Sprintf("- Suggestion: %s\n\n", suggestionForFinding(f)))
	}
	return sb.String()
}

func dedupeForReport(in []model.Finding) []findingView {
	if len(in) == 0 {
		return nil
	}
	type agg struct {
		view findingView
	}
	byKey := map[string]agg{}
	for _, f := range in {
		key := reportKey(f)
		cur, ok := byKey[key]
		if !ok {
			byKey[key] = agg{
				view: findingView{
					URL:         f.URL,
					Param:       f.Param,
					Payload:     f.InjectedValue,
					Context:     f.Context,
					Evidence:    f.Indicator,
					Occurrences: 1,
				},
			}
			continue
		}
		cur.view.Occurrences++
		if len(strings.TrimSpace(f.Indicator)) > len(strings.TrimSpace(cur.view.Evidence)) {
			cur.view.Evidence = f.Indicator
			cur.view.Payload = f.InjectedValue
			cur.view.Context = f.Context
			cur.view.URL = f.URL
		}
		byKey[key] = cur
	}
	out := make([]findingView, 0, len(byKey))
	for _, a := range byKey {
		out = append(out, a.view)
	}
	return out
}

func reportKey(f model.Finding) string {
	u, err := url.Parse(strings.TrimSpace(f.URL))
	host := ""
	path := strings.TrimSpace(f.URL)
	if err == nil {
		host = strings.ToLower(strings.TrimSpace(u.Hostname()))
		path = strings.TrimSpace(u.Path)
		if path == "" {
			path = "/"
		}
	}
	param := strings.ToLower(strings.TrimSpace(f.Param))
	return host + "|" + path + "|" + param
}

func suggestionForFinding(f findingView) string {
	ctx := strings.ToLower(strings.TrimSpace(f.Context))
	payload := f.Payload
	switch ctx {
	case "comment":
		return fmt.Sprintf("Comment context reflection found. Verify payload `%s` in a browser and check real execution impact.", payload)
	case "html_text":
		return fmt.Sprintf("HTML text reflection found. Verify whether payload `%s` can break structure and execute.", payload)
	case "attribute_value:key", "attribute_value:event_attr", "attribute_value:special_attr", "attribute_value":
		return fmt.Sprintf("Attribute context reflection found. Verify payload `%s` for quote-breakout/event-handler execution.", payload)
	case "script", "script:string_break", "script:line_comment", "script:block_comment", "script:identifier":
		return fmt.Sprintf("Script context reflection found. Verify payload `%s` for executable JavaScript behavior.", payload)
	default:
		return fmt.Sprintf("Reflected XSS candidate found. Verify payload `%s` manually in authorized scope.", payload)
	}
}
