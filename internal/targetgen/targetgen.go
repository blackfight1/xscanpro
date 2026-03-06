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

	globalParams = util.UniqueStrings(globalParams)
	sort.Strings(globalParams)

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
		params := buildParamList(canon, globalParams, opt)
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

		params := buildParamList(canon, globalParams, opt)

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

func buildParamList(rawURL string, globalParams []string, opt Options) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	paramSet := map[string]struct{}{}
	for k := range u.Query() {
		paramSet[k] = struct{}{}
	}
	for _, p := range globalParams {
		paramSet[p] = struct{}{}
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
