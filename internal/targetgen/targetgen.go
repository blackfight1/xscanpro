package targetgen

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"xscanpro/internal/model"
	"xscanpro/internal/util"
)

type Options struct {
	MaxParamsPerURL int
	AllParams       bool
	SmartDedupe     bool
	MaxPerPattern   int
	ParamStrategy   string
	RelatedParams   map[string][]string
	HighValueParams []string
}

var numRegex = regexp.MustCompile(`\d+`)
var uuidRegex = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
var hexLongRegex = regexp.MustCompile(`(?i)[0-9a-f]{12,}`)

func BuildTargets(domain string, urls []string, endpoints []string, globalParams []string, opt Options) []model.ScanTarget {
	if opt.MaxParamsPerURL <= 0 {
		opt.MaxParamsPerURL = 20
	}
	if opt.MaxPerPattern <= 0 {
		opt.MaxPerPattern = 4
	}

	strategy := strings.ToLower(strings.TrimSpace(opt.ParamStrategy))
	if strategy != "batch" && strategy != "deep" {
		strategy = "batch"
	}
	globalParams = util.UniqueStrings(globalParams)
	sort.Strings(globalParams)
	opt.HighValueParams = util.UniqueStrings(opt.HighValueParams)
	sort.Strings(opt.HighValueParams)

	targets := make([]model.ScanTarget, 0, len(urls)+len(endpoints))
	seenURL := map[string]struct{}{}
	patternCounter := map[string]int{}

	// Always keep crawled URLs (scope matched) to avoid dropping known vulnerable pages.
	baseURLs := util.UniqueStrings(append([]string(nil), urls...))
	sort.Strings(baseURLs)
	for _, raw := range baseURLs {
		u, err := url.Parse(raw)
		if err != nil || !util.ScopeMatch(u.Hostname(), domain) {
			continue
		}
		canon, err := util.CanonicalURL(raw)
		if err != nil {
			continue
		}
		if _, ok := seenURL[canon]; ok {
			continue
		}
		seenURL[canon] = struct{}{}
		params := buildParamList(canon, globalParams, strategy, opt)
		targets = append(targets, model.ScanTarget{
			URL:    canon,
			Params: params,
		})
	}

	// For discovered endpoints, apply smart dedupe controls.
	extraEndpoints := util.UniqueStrings(append([]string(nil), endpoints...))
	sort.Strings(extraEndpoints)
	for _, raw := range extraEndpoints {
		u, err := url.Parse(raw)
		if err != nil || !util.ScopeMatch(u.Hostname(), domain) {
			continue
		}
		canon, err := util.CanonicalURL(raw)
		if err != nil {
			continue
		}
		if _, ok := seenURL[canon]; ok {
			continue
		}

		params := buildParamList(canon, globalParams, strategy, opt)

		if opt.SmartDedupe {
			key := patternKey(canon, params)
			if patternCounter[key] >= opt.MaxPerPattern {
				continue
			}
			patternCounter[key]++
		}
		seenURL[canon] = struct{}{}

		targets = append(targets, model.ScanTarget{
			URL:    canon,
			Params: params,
		})
	}
	return targets
}

func buildParamList(rawURL string, globalParams []string, strategy string, opt Options) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	paramSet := map[string]struct{}{}
	for k := range u.Query() {
		paramSet[k] = struct{}{}
	}
	if strategy == "batch" {
		for _, p := range relatedParamsForURL(rawURL, opt.RelatedParams) {
			paramSet[p] = struct{}{}
		}
		for _, p := range opt.HighValueParams {
			paramSet[p] = struct{}{}
		}
	} else {
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
	}
	params := make([]string, 0, len(paramSet))
	for p := range paramSet {
		params = append(params, p)
	}
	sort.Strings(params)
	if !opt.AllParams && len(params) > opt.MaxParamsPerURL {
		params = params[:opt.MaxParamsPerURL]
	}
	return params
}

func relatedParamsForURL(rawURL string, related map[string][]string) []string {
	if len(related) == 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	set := map[string]struct{}{}
	for _, p := range related[host+"|/"] {
		set[p] = struct{}{}
	}
	for _, word := range pathWords(rawURL) {
		for _, p := range related[host+"|"+word] {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func pathWords(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	parts := strings.Split(u.Path, "/")
	set := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.LastIndex(part, "."); i > 0 {
			part = part[:i]
		}
		for _, sub := range splitCamelSnake(part) {
			sub = strings.ToLower(numRegex.ReplaceAllString(sub, ""))
			sub = strings.Trim(sub, "-_.")
			if len(sub) >= 2 {
				set[sub] = struct{}{}
			}
		}
		part = strings.ToLower(numRegex.ReplaceAllString(part, ""))
		part = strings.Trim(part, "-_.")
		if len(part) >= 2 {
			set[part] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func splitCamelSnake(s string) []string {
	if strings.Contains(s, "_") {
		return strings.Split(s, "_")
	}
	re := regexp.MustCompile(`[A-Z][a-z]+|[a-z]+|[A-Z]+`)
	m := re.FindAllString(s, -1)
	out := make([]string, 0, len(m))
	for _, x := range m {
		if len(x) >= 2 {
			out = append(out, x)
		}
	}
	return out
}

func patternKey(raw string, params []string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	pathMarked := markPath(u.Path)
	paramKeys := make([]string, 0, len(params))
	paramKeys = append(paramKeys, params...)
	sort.Strings(paramKeys)
	if len(paramKeys) > 12 {
		paramKeys = paramKeys[:12]
	}
	return fmt.Sprintf("%s|%s|%s", strings.ToLower(u.Hostname()), pathMarked, strings.Join(paramKeys, ","))
}

func markPath(p string) string {
	p = uuidRegex.ReplaceAllString(p, "{uuid}")
	p = hexLongRegex.ReplaceAllString(p, "{hex}")
	p = numRegex.ReplaceAllString(p, "{n}")
	return p
}
