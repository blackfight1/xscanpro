package jsfinder

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xscanpro/internal/fetch"
	"xscanpro/internal/model"
	"xscanpro/internal/util"
)

var (
	fullURLRe          = regexp.MustCompile(`(?i)(?:["'\x60\s\n\r=:(,]|^)((?:https?|wss?)://[^\s"'<>\x60),;]+)`)
	protocolRelativeRe = regexp.MustCompile(`(?i)(?:["'\x60\s\n\r=:(,]|^)(//[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}[^\s"'<>\x60),;]*)`)
	apiPathRe          = regexp.MustCompile(`(?i)(?:["'\x60\s\n\r=:(,]|^)(/(?:api|v[0-9]|graphql|rest|ajax|auth|user|account|admin|search|query|order|product|cart|checkout|payment|message|comment|report|upload|download|config|setting)[a-z0-9_\-/.?=&#]*)(?:["'\x60\s\n\r),;]|$)`)
	relPathRe          = regexp.MustCompile(`(?i)(?:["'\x60\s\n\r=:(,]|^)((?:/[a-z0-9_\-/.?=&#]+)|(?:\.\.?/[a-z0-9_\-/.?=&#]+))(?:["'\x60\s\n\r),;]|$)`)
	generalPathRe      = regexp.MustCompile(`(?i)(?:["'\x60\s\n\r=:(,]|^)(/[a-z][a-z0-9_\-/.?=&#]{2,})(?:["'\x60\s\n\r),;]|$)`)
	propertyURLRe      = regexp.MustCompile(`(?i)(?:url|endpoint|path|route|href|src|action|data-url|api|link)\s*[:=]\s*["'\x60]([^\s"'\x60]{2,})["'\x60]`)
	fetchCallRe        = regexp.MustCompile(`(?i)(?:fetch|axios|ajax|request|get|post|put|delete|patch)\s*\(\s*["'\x60]([^\s"'\x60)]+)["'\x60]`)
	urlCtorRe          = regexp.MustCompile(`(?i)new\s+URL\s*\(\s*["'\x60]([^\s"'\x60)]+)["'\x60]`)
	locationAssignRe   = regexp.MustCompile(`(?i)(?:location|window\.location)(?:\.\w+)?\s*=\s*["'\x60]([^\s"'\x60]{2,})["'\x60]`)
	htmlAttrRe         = regexp.MustCompile(`(?i)(?:href|src|action|data-url|data-href|data-src|data-endpoint)\s*=\s*["']([^"']{2,})["']`)
	sourceMapRe        = regexp.MustCompile(`(?i)(?:sourceMappingURL|X-SourceMap|SourceMap)\s*[=:]\s*(\S+)`)
	templatePathRe     = regexp.MustCompile("`" + `([^` + "`" + `]*?/[a-zA-Z0-9_\-/.?=&#${}]+[^` + "`" + `]*?)` + "`")
	base64StringRe     = regexp.MustCompile(`["']([A-Za-z0-9+/]{28,}={0,2})["']`)
	queryParamRe       = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=`)
	jsonKeyRe          = regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_\-]{1,40})"\s*:`)
	jsonKeySingleRe    = regexp.MustCompile(`'([a-zA-Z_][a-zA-Z0-9_\-]{1,40})'\s*:`)
	jsonKeyBareRe      = regexp.MustCompile(`[{,]\s*([a-zA-Z_][a-zA-Z0-9_\-]{1,40})\s*:`)
	htmlInputNameRe    = regexp.MustCompile(`(?i)<(?:input|textarea|select|button)[^>]*\sname\s*=\s*["']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["']`)
	htmlInputIDRe      = regexp.MustCompile(`(?i)<(?:input|textarea|select|button)[^>]*\sid\s*=\s*["']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["']`)
	formDataRe         = regexp.MustCompile(`\.append\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["']`)
	jsVarRe            = regexp.MustCompile(`(?:let|var|const)\s+([a-zA-Z_][a-zA-Z0-9_\-]{1,40})\s*[=;]`)
	apiParamObjKeyRe   = regexp.MustCompile(`(?i)(?:data|params|body|query|form|payload|request)[\s\S]{0,120}["']?([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["']?\s*:`)
	validParamRe       = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_\-]{1,40}$`)
	paramDigitsHeavyRe = regexp.MustCompile(`\d{4,}`)
	allDigitsRe        = regexp.MustCompile(`^\d+$`)
	templateVarRe      = regexp.MustCompile(`\$\{[^}]+\}`)
)

var defaultLinkExclusions = []string{
	".css", ".jpg", ".jpeg", ".png", ".svg", ".gif", ".webp", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".mov",
	".pdf", ".zip", ".rar", ".tar", ".gz",
	"jquery", "bootstrap", "fontawesome", "googleapis.com", "gstatic.com",
}

var defaultParamExclusions = map[string]struct{}{
	"i": {}, "j": {}, "k": {}, "x": {}, "y": {}, "z": {},
	"el": {}, "fn": {}, "cb": {}, "err": {}, "res": {}, "req": {}, "obj": {}, "val": {}, "tmp": {},
	"this": {}, "self": {}, "that": {}, "args": {}, "opts": {}, "ctx": {}, "cfg": {},
	"undefined": {}, "null": {}, "true": {}, "false": {},
	"if": {}, "else": {}, "for": {}, "while": {}, "return": {}, "var": {}, "let": {}, "const": {}, "function": {},
	"window": {}, "document": {}, "console": {}, "navigator": {}, "history": {},
}

type Finder struct {
	client      *fetch.Client
	domain      string
	workerCount int
	verbose     bool
}

const (
	// Parse full content when size <= 2MB.
	jsFullParseLimitBytes = 2 * 1024 * 1024
	// For oversized JS, keep only a sampled slice (head+tail) to reduce CPU/memory pressure.
	jsDowngradeSampleBytes = 256 * 1024
)

func New(client *fetch.Client, domain string, workers int, verbose bool) *Finder {
	return &Finder{
		client:      client,
		domain:      strings.ToLower(domain),
		workerCount: workers,
		verbose:     verbose,
	}
}

func (f *Finder) Discover(jsURLs []string) model.JSDiscovery {
	jsURLs = util.UniqueStrings(jsURLs)
	var out model.JSDiscovery
	out.RelatedParams = map[string][]string{}
	sem := make(chan struct{}, f.workerCount)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var hashMu sync.Mutex
	seenContentHash := map[string]struct{}{}
	var processed int32
	var dedupedByHash int32
	var downgradedLarge int32
	total := int32(len(jsURLs))

	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	done := make(chan struct{})
	startedAt := time.Now()
	go func() {
		for {
			select {
			case <-ticker.C:
				p := atomic.LoadInt32(&processed)
				line := util.RenderProgressLine(
					"  > js discovery",
					int64(p),
					int64(total),
					22,
					startedAt,
					"",
				)
				fmt.Printf("\r%s", line)
			case <-done:
				return
			}
		}
	}()

	for _, jsURL := range jsURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() {
				<-sem
				atomic.AddInt32(&processed, 1)
			}()

			status, body, contentType, err := f.client.Get(u)
			if err != nil || status < 200 || status >= 400 {
				return
			}
			if !isLikelyJS(u, contentType) {
				return
			}

			hash := bodyHash(body)
			hashMu.Lock()
			if _, ok := seenContentHash[hash]; ok {
				hashMu.Unlock()
				atomic.AddInt32(&dedupedByHash, 1)
				return
			}
			seenContentHash[hash] = struct{}{}
			hashMu.Unlock()

			var isDowngraded bool
			body, isDowngraded = sampleLargeJS(body)
			if isDowngraded {
				atomic.AddInt32(&downgradedLarge, 1)
			}

			body = normalize(body)
			body = tryDecodeBase64Strings(body)
			endpoints, params := f.extractFromJS(u, body)
			relatedKeys := relatedKeysFromJS(u, endpoints)

			mu.Lock()
			out.Endpoints = append(out.Endpoints, endpoints...)
			out.Params = append(out.Params, params...)
			for _, key := range relatedKeys {
				out.RelatedParams[key] = append(out.RelatedParams[key], params...)
			}
			mu.Unlock()
		}(jsURL)
	}
	wg.Wait()
	close(done)
	finalLine := util.RenderProgressLine(
		"  > js discovery",
		int64(total),
		int64(total),
		22,
		startedAt,
		"done",
	)
	fmt.Printf("\r%s\n", finalLine)
	if f.verbose {
		fmt.Printf("  - js dedupe:       content_hash_skipped=%d, large_js_downgraded=%d\n",
			atomic.LoadInt32(&dedupedByHash),
			atomic.LoadInt32(&downgradedLarge),
		)
	}

	out.Endpoints = util.UniqueStrings(out.Endpoints)
	out.Params = util.UniqueStrings(out.Params)
	for key, params := range out.RelatedParams {
		out.RelatedParams[key] = util.UniqueStrings(params)
	}
	return out
}

func relatedKeysFromJS(origin string, endpoints []string) []string {
	set := map[string]struct{}{}
	for _, key := range relatedKeysFromURL(origin) {
		set[key] = struct{}{}
	}
	for _, endpoint := range endpoints {
		for _, key := range relatedKeysFromURL(endpoint) {
			set[key] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func relatedKeysFromURL(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	set := map[string]struct{}{
		host + "|/": {},
	}
	for _, word := range extractPathWords(raw) {
		if cp := cleanParam(word); cp != "" && !shouldExcludeParam(cp) {
			set[host+"|"+cp] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func bodyHash(body string) string {
	sum := sha1.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

func sampleLargeJS(body string) (string, bool) {
	if len(body) <= jsFullParseLimitBytes {
		return body, false
	}

	headSize := jsDowngradeSampleBytes * 3 / 4
	tailSize := jsDowngradeSampleBytes - headSize
	if headSize > len(body) {
		headSize = len(body)
	}
	if tailSize > len(body)-headSize {
		tailSize = len(body) - headSize
	}
	if tailSize < 0 {
		tailSize = 0
	}

	head := body[:headSize]
	tail := ""
	if tailSize > 0 {
		tail = body[len(body)-tailSize:]
	}
	sampled := head + "\n/* xscanpro: oversized js downgraded */\n" + tail
	return sampled, true
}

func (f *Finder) extractFromJS(origin, content string) ([]string, []string) {
	endpointSet := make(map[string]struct{})
	paramSet := make(map[string]struct{})

	for _, cand := range extractLinkCandidates(content) {
		cand = cleanLink(cand)
		if cand == "" || shouldExcludeLink(cand) {
			continue
		}
		full, ok := resolveCandidate(origin, cand)
		if !ok {
			continue
		}
		parsed, err := url.Parse(full)
		if err != nil || !util.ScopeMatch(parsed.Hostname(), f.domain) {
			continue
		}
		canon, err := util.CanonicalURL(full)
		if err != nil {
			continue
		}
		endpointSet[canon] = struct{}{}
		for _, p := range extractPathWords(canon) {
			if cp := cleanParam(p); cp != "" && !shouldExcludeParam(cp) {
				paramSet[cp] = struct{}{}
			}
		}
	}

	for _, p := range extractParamCandidates(content) {
		if cp := cleanParam(p); cp != "" && !shouldExcludeParam(cp) {
			paramSet[cp] = struct{}{}
		}
	}

	endpoints := make([]string, 0, len(endpointSet))
	for ep := range endpointSet {
		endpoints = append(endpoints, ep)
	}
	params := make([]string, 0, len(paramSet))
	for p := range paramSet {
		params = append(params, p)
	}
	return util.UniqueStrings(endpoints), util.UniqueStrings(params)
}

func extractLinkCandidates(content string) []string {
	res := make([]string, 0, 256)
	res = append(res, extractMatches(fullURLRe, content)...)
	res = append(res, extractMatches(protocolRelativeRe, content)...)
	res = append(res, extractMatches(apiPathRe, content)...)
	res = append(res, extractMatches(relPathRe, content)...)
	res = append(res, extractMatches(generalPathRe, content)...)
	res = append(res, extractMatches(propertyURLRe, content)...)
	res = append(res, extractMatches(fetchCallRe, content)...)
	res = append(res, extractMatches(urlCtorRe, content)...)
	res = append(res, extractMatches(locationAssignRe, content)...)
	res = append(res, extractMatches(htmlAttrRe, content)...)
	res = append(res, extractMatches(sourceMapRe, content)...)

	for _, tm := range extractMatches(templatePathRe, content) {
		if !strings.Contains(tm, "/") {
			continue
		}
		cleaned := templateVarRe.ReplaceAllString(tm, "{VAR}")
		if strings.HasPrefix(cleaned, "/") || strings.Contains(cleaned, "://") {
			res = append(res, cleaned)
		}
	}
	return res
}

func extractParamCandidates(content string) []string {
	res := make([]string, 0, 256)
	res = append(res, extractMatches(queryParamRe, content)...)
	res = append(res, extractMatches(jsonKeyRe, content)...)
	res = append(res, extractMatches(jsonKeySingleRe, content)...)
	res = append(res, extractMatches(jsonKeyBareRe, content)...)
	res = append(res, extractMatches(htmlInputNameRe, content)...)
	res = append(res, extractMatches(htmlInputIDRe, content)...)
	res = append(res, extractMatches(formDataRe, content)...)
	res = append(res, extractMatches(jsVarRe, content)...)
	res = append(res, extractMatches(apiParamObjKeyRe, content)...)
	return res
}

func normalize(s string) string {
	s = strings.ReplaceAll(s, `\/`, `/`)
	s = strings.ReplaceAll(s, `\u002f`, `/`)
	s = strings.ReplaceAll(s, `\u002F`, `/`)
	s = strings.ReplaceAll(s, `\u003a`, ":")
	s = strings.ReplaceAll(s, `\u003A`, ":")
	s = strings.ReplaceAll(s, `\u003f`, `?`)
	s = strings.ReplaceAll(s, `\u003F`, `?`)
	s = strings.ReplaceAll(s, `\u0026`, `&`)
	s = strings.ReplaceAll(s, `\u003d`, `=`)
	s = strings.ReplaceAll(s, `\x2f`, `/`)
	s = strings.ReplaceAll(s, `\x2F`, `/`)
	s = strings.ReplaceAll(s, `\x3a`, ":")
	s = strings.ReplaceAll(s, `\x3A`, ":")
	s = strings.ReplaceAll(s, `\x3f`, `?`)
	s = strings.ReplaceAll(s, `\x3F`, `?`)
	s = strings.ReplaceAll(s, `\x26`, `&`)
	s = strings.ReplaceAll(s, `\x3d`, `=`)
	s = strings.ReplaceAll(s, `%2f`, `/`)
	s = strings.ReplaceAll(s, `%2F`, `/`)
	s = strings.ReplaceAll(s, `%3a`, ":")
	s = strings.ReplaceAll(s, `%3A`, ":")
	s = strings.ReplaceAll(s, `%3f`, `?`)
	s = strings.ReplaceAll(s, `%3F`, `?`)
	s = html.UnescapeString(s)
	return s
}

func tryDecodeBase64Strings(content string) string {
	matches := base64StringRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return content
	}
	decoded := content
	limit := 16
	for i, m := range matches {
		if i >= limit {
			break
		}
		if len(m) < 2 {
			continue
		}
		raw := m[1]
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		s := string(b)
		if strings.Contains(s, "/") || strings.Contains(s, "http") || strings.Contains(s, "api") {
			decoded += "\n" + s
		}
	}
	return decoded
}

func resolveCandidate(baseURL, ref string) (string, bool) {
	if strings.HasPrefix(ref, "//") {
		b, err := url.Parse(baseURL)
		if err != nil || b.Scheme == "" {
			return "", false
		}
		return b.Scheme + ":" + ref, true
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") ||
		strings.HasPrefix(ref, "ws://") || strings.HasPrefix(ref, "wss://") {
		return ref, true
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(r)
	if resolved.Scheme == "" || resolved.Host == "" {
		return "", false
	}
	s := strings.ToLower(resolved.Scheme)
	if s != "http" && s != "https" {
		return "", false
	}
	return resolved.String(), true
}

func cleanLink(link string) string {
	link = strings.TrimSpace(link)
	link = strings.Trim(link, "\"'`")
	link = stripUnbalancedBrackets(link)
	link = strings.TrimSuffix(link, "\\")
	link = strings.TrimSuffix(link, ";")
	link = strings.TrimSuffix(link, ",")

	if len(link) < 2 {
		return ""
	}
	if strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "#/") {
		return ""
	}
	if strings.HasPrefix(link, "$") || strings.HasPrefix(link, "\\") {
		return ""
	}
	if strings.Contains(link, "{{") || strings.Contains(link, "}}") {
		return ""
	}
	if strings.Contains(link, "${") && !strings.Contains(link, "{VAR}") {
		return ""
	}
	if strings.HasPrefix(link, "{") && strings.HasSuffix(link, "}") {
		return ""
	}
	return link
}

func shouldExcludeLink(link string) bool {
	ll := strings.ToLower(link)
	for _, exc := range defaultLinkExclusions {
		if strings.Contains(ll, exc) {
			return true
		}
	}
	return false
}

func cleanParam(param string) string {
	param = strings.TrimSpace(param)
	param = strings.Trim(param, "\"'`")
	param = strings.TrimSpace(strings.ToLower(param))
	if !validParamRe.MatchString(param) {
		return ""
	}
	if len(param) < 2 || len(param) > 41 {
		return ""
	}
	return param
}

func shouldExcludeParam(param string) bool {
	if _, ok := defaultParamExclusions[param]; ok {
		return true
	}
	if paramDigitsHeavyRe.MatchString(param) {
		return true
	}
	if allDigitsRe.MatchString(param) {
		return true
	}
	return false
}

func extractPathWords(urlStr string) []string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	parts := strings.Split(u.Path, "/")
	var words []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.LastIndex(part, "."); i > 0 {
			part = part[:i]
		}
		for _, sub := range splitCamelSnake(part) {
			sub = strings.ToLower(sub)
			if validParamRe.MatchString(sub) {
				words = append(words, sub)
			}
		}
		part = strings.ToLower(part)
		if validParamRe.MatchString(part) {
			words = append(words, part)
		}
	}
	return words
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

func stripUnbalancedBrackets(link string) string {
	pairs := [][2]byte{{'(', ')'}, {'[', ']'}, {'{', '}'}}
	for _, pair := range pairs {
		open := 0
		for i := 0; i < len(link); i++ {
			if link[i] == pair[0] {
				open++
			} else if link[i] == pair[1] {
				open--
				if open < 0 {
					link = link[:i]
					break
				}
			}
		}
		for open > 0 {
			idx := strings.LastIndexByte(link, pair[0])
			if idx < 0 {
				break
			}
			link = link[:idx] + link[idx+1:]
			open--
		}
	}
	return link
}

func isLikelyJS(u, ct string) bool {
	lcCT := strings.ToLower(ct)
	lu := strings.ToLower(u)
	if strings.Contains(lcCT, "javascript") || strings.Contains(lcCT, "ecmascript") || strings.Contains(lcCT, "text/plain") {
		return true
	}
	if strings.Contains(lu, ".js") || strings.Contains(lu, ".mjs") || strings.Contains(lu, ".jsx") {
		return true
	}
	return false
}

func extractMatches(re *regexp.Regexp, content string) []string {
	matches := re.FindAllStringSubmatch(content, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return out
}
