package scanner

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	inputNameRe = regexp.MustCompile(`(?i)<input[^>]+name=["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']`)
	jsVarRe     = regexp.MustCompile(`(?i)\b(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]{1,30})\b`)
	scriptTagRe = regexp.MustCompile(`(?is)<script[^>]*>[\s\S]*?%s[\s\S]*?</script>`)
	attrValRe   = regexp.MustCompile(`(?is)[a-zA-Z_:][-a-zA-Z0-9_:.]*\s*=\s*["'][^"']*%s[^"']*["']`)
	commentRe   = regexp.MustCompile(`(?is)<!--[\s\S]*?%s[\s\S]*?-->`)

	tplNumRe        = regexp.MustCompile(`\d+`)
	tplUUIDRe       = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	tplHexRe        = regexp.MustCompile(`(?i)[0-9a-f]{12,}`)
	shapeUUIDRe     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	shapeNumRe      = regexp.MustCompile(`^[+-]?(?:\d+|\d+\.\d+)$`)
	shapeHexRe      = regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`)
	shapeAlphaRe    = regexp.MustCompile(`^[a-zA-Z]+$`)
	shapeAlphaNumRe = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	shapeDateRe     = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}$`)
	shapeUnicodeRe  = regexp.MustCompile(`(?i)^(?:\\u[0-9a-f]{4})+$`)
	shapeURLEncRe   = regexp.MustCompile(`(?i)(?:%[0-9a-f]{2})+`)
	shapeHTMLRe     = regexp.MustCompile(`(?i)<[a-z!/][^>]*>`)
	scriptBlockFind = regexp.MustCompile(`(?is)<script[^>]*>([\s\S]*?)</script>`)
	numInKeyRe      = regexp.MustCompile(`\d+`)
)

type evidence struct {
	Context   string
	Indicator string
}

type semanticProbe struct {
	Context   string
	Payload   string
	Token     string
	Indicator string
}

type Scanner struct {
	client              *fetch.Client
	workerCount         int
	quickWorkers        int
	verifyWorkers       int
	targetWorkers       int
	maxParams           int
	allParams           bool
	paramBatchSize      int
	samplePerGroup      int
	expandOnHit         bool
	shapeDedupeEnabled  bool
	shapeThreshold      int
	paramStrategy       string
	highValueParamSet   map[string]struct{}
	batchHiddenParamCap int
	batchVerifyProbeCap int
	onFinding           func(model.Finding)
	verbose             bool
}

type scopedTarget struct {
	target   model.ScanTarget
	groupKey string
}

type quickTask struct {
	baseURL  string
	params   []string
	groupKey string
}

type verifyTask struct {
	baseURL    string
	param      string
	marker     string
	contexts   []string
	batchCtx   map[string]string
	findingURL string
	lines      []int
	groupKey   string
}

type findingResult struct {
	finding  model.Finding
	groupKey string
}

func New(client *fetch.Client, workers, maxParams int, verbose bool) *Scanner {
	if workers <= 0 {
		workers = 20
	}
	quick := workers * 6 / 10
	if quick < 2 {
		quick = 2
	}
	verify := workers * 3 / 10
	if verify < 1 {
		verify = 1
	}
	target := workers - quick - verify
	if target < 1 {
		target = 1
	}
	return &Scanner{
		client:              client,
		workerCount:         workers,
		quickWorkers:        quick,
		verifyWorkers:       verify,
		targetWorkers:       target,
		maxParams:           maxParams,
		allParams:           true,
		paramBatchSize:      45,
		samplePerGroup:      0,
		expandOnHit:         true,
		shapeDedupeEnabled:  true,
		shapeThreshold:      4,
		paramStrategy:       "deep",
		highValueParamSet:   map[string]struct{}{},
		batchHiddenParamCap: 6,
		batchVerifyProbeCap: 4,
		verbose:             verbose,
	}
}

func (s *Scanner) SetTemplateStrategy(samplePerGroup int, expandOnHit bool) {
	// samplePerGroup <= 0 means disable template sampling (xscan-like behavior).
	s.samplePerGroup = samplePerGroup
	s.expandOnHit = expandOnHit
}

func (s *Scanner) SetBatchStrategy(allParams bool, batchSize int) {
	s.allParams = allParams
	if batchSize > 0 {
		s.paramBatchSize = batchSize
	}
}

func (s *Scanner) SetWorkerSplit(targetWorkers, quickWorkers, verifyWorkers int) {
	if targetWorkers <= 0 || quickWorkers <= 0 || verifyWorkers <= 0 {
		return
	}
	s.targetWorkers = targetWorkers
	s.quickWorkers = quickWorkers
	s.verifyWorkers = verifyWorkers
	s.workerCount = targetWorkers + quickWorkers + verifyWorkers
}

func (s *Scanner) SetShapeDedupe(enabled bool, threshold int) {
	s.shapeDedupeEnabled = enabled
	if threshold > 0 {
		s.shapeThreshold = threshold
	}
}

func (s *Scanner) SetFindingCallback(fn func(model.Finding)) {
	s.onFinding = fn
}
func (s *Scanner) SetParamStrategy(strategy string, highValueParams []string) {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy != "batch" && strategy != "deep" {
		strategy = "deep"
	}
	s.paramStrategy = strategy
	s.highValueParamSet = map[string]struct{}{}
	for _, p := range highValueParams {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		s.highValueParamSet[p] = struct{}{}
	}
}

func (s *Scanner) Scan(targets []model.ScanTarget) model.Report {
	if len(targets) == 0 {
		return model.Report{TotalTargets: 0, TotalFindings: 0, Findings: nil}
	}

	groups := groupByTemplate(targets)
	phase1, phase2, totalGrouped := buildScanPhases(groups, s.samplePerGroup)

	if s.verbose {
		fmt.Printf("  - templates:       groups=%d, sample_targets=%d, deferred=%d\n", len(groups), len(phase1), len(phase2))
	}

	findings1, hitGroups := s.scanBatch("sample", phase1)
	findings := findings1

	scanned := len(phase1)
	if s.expandOnHit && len(hitGroups) > 0 && len(phase2) > 0 {
		expand := filterByGroup(phase2, hitGroups)
		scanned += len(expand)
		if s.verbose {
			fmt.Printf("  - expand:          hit_groups=%d, expand_targets=%d\n", len(hitGroups), len(expand))
		}
		findings2, _ := s.scanBatch("expand", expand)
		findings = append(findings, findings2...)
	}

	findings = dedupeFindings(findings)

	if s.verbose {
		skipped := totalGrouped - scanned
		if skipped < 0 {
			skipped = 0
		}
		fmt.Printf("  - scan summary:    scanned=%d/%d, skipped_similar=%d, findings=%d\n", scanned, totalGrouped, skipped, len(findings))
	}

	return model.Report{
		TotalTargets:  len(targets),
		TotalFindings: len(findings),
		Findings:      findings,
	}
}

func groupByTemplate(targets []model.ScanTarget) map[string][]model.ScanTarget {
	groups := make(map[string][]model.ScanTarget)
	for _, t := range targets {
		key := templateKey(t.URL)
		groups[key] = append(groups[key], t)
	}
	for k := range groups {
		sort.Slice(groups[k], func(i, j int) bool {
			return groups[k][i].URL < groups[k][j].URL
		})
	}
	return groups
}

func buildScanPhases(groups map[string][]model.ScanTarget, samplePerGroup int) ([]scopedTarget, []scopedTarget, int) {
	if samplePerGroup <= 0 {
		keys := make([]string, 0, len(groups))
		total := 0
		for k, arr := range groups {
			keys = append(keys, k)
			total += len(arr)
		}
		sort.Strings(keys)
		phase1 := make([]scopedTarget, 0, total)
		for _, k := range keys {
			for _, t := range groups[k] {
				phase1 = append(phase1, scopedTarget{target: t, groupKey: k})
			}
		}
		return phase1, nil, total
	}
	keys := make([]string, 0, len(groups))
	total := 0
	for k, arr := range groups {
		keys = append(keys, k)
		total += len(arr)
	}
	sort.Strings(keys)

	phase1 := make([]scopedTarget, 0, len(keys)*samplePerGroup)
	phase2 := make([]scopedTarget, 0, total)
	for _, k := range keys {
		arr := groups[k]
		priority := make([]model.ScanTarget, 0, len(arr))
		normal := make([]model.ScanTarget, 0, len(arr))
		for _, t := range arr {
			if hasQuery(t.URL) {
				priority = append(priority, t)
			} else {
				normal = append(normal, t)
			}
		}
		// Always scan query-bearing URLs in phase-1 to avoid missing known vulnerable links.
		for _, t := range priority {
			phase1 = append(phase1, scopedTarget{target: t, groupKey: k})
		}
		n := samplePerGroup
		if n > len(normal) {
			n = len(normal)
		}
		for i := 0; i < n; i++ {
			phase1 = append(phase1, scopedTarget{target: normal[i], groupKey: k})
		}
		for i := n; i < len(normal); i++ {
			phase2 = append(phase2, scopedTarget{target: normal[i], groupKey: k})
		}
	}
	return phase1, phase2, total
}

func hasQuery(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.RawQuery != ""
}

func filterByGroup(in []scopedTarget, hit map[string]bool) []scopedTarget {
	out := make([]scopedTarget, 0, len(in))
	for _, t := range in {
		if hit[t.groupKey] {
			out = append(out, t)
		}
	}
	return out
}

func (s *Scanner) scanBatch(label string, targets []scopedTarget) ([]model.Finding, map[string]bool) {
	if len(targets) == 0 {
		return nil, map[string]bool{}
	}

	targetCh := make(chan scopedTarget)
	quickCh := make(chan quickTask, s.quickWorkers*4)
	verifyCh := make(chan verifyTask, s.verifyWorkers*4)
	findingCh := make(chan findingResult, s.verifyWorkers*4)

	var targetDone sync.WaitGroup
	var quickDone sync.WaitGroup
	var verifyDone sync.WaitGroup

	var processedTargets int32
	var skippedByShape int32
	var generatedBatches int32
	var generatedParams int32
	var processedBatches int32
	var processedVerify int32
	var findingCount int32

	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	stopProgress := make(chan struct{})
	shapeCounter := map[string]int{}
	var shapeMu sync.Mutex
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Printf("\r  > phase=%s | targets %d/%d | skip-shape %d | quick %d/%d | params %d | verify %d | findings %d",
					label,
					atomic.LoadInt32(&processedTargets),
					int32(len(targets)),
					atomic.LoadInt32(&skippedByShape),
					atomic.LoadInt32(&processedBatches),
					atomic.LoadInt32(&generatedBatches),
					atomic.LoadInt32(&generatedParams),
					atomic.LoadInt32(&processedVerify),
					atomic.LoadInt32(&findingCount),
				)
			case <-stopProgress:
				return
			}
		}
	}()

	for i := 0; i < s.targetWorkers; i++ {
		targetDone.Add(1)
		go func() {
			defer targetDone.Done()
			for t := range targetCh {
				params, ok := s.prepareParams(t.target)
				if ok {
					batches := chunkParams(params, s.paramBatchSize)
					for _, batch := range batches {
						quickCh <- quickTask{baseURL: t.target.URL, params: batch, groupKey: t.groupKey}
						atomic.AddInt32(&generatedBatches, 1)
						atomic.AddInt32(&generatedParams, int32(len(batch)))
					}
				}
				atomic.AddInt32(&processedTargets, 1)
			}
		}()
	}

	for i := 0; i < s.quickWorkers; i++ {
		quickDone.Add(1)
		go func() {
			defer quickDone.Done()
			for task := range quickCh {
				if s.shapeDedupeEnabled {
					fp := smartRequestFingerprint(task.baseURL, task.params)
					shapeMu.Lock()
					shapeCounter[fp]++
					count := shapeCounter[fp]
					shapeMu.Unlock()
					if count > s.shapeThreshold {
						atomic.AddInt32(&skippedByShape, 1)
						atomic.AddInt32(&processedBatches, 1)
						continue
					}
				}
				vs := s.quickReflectBatch(task)
				for _, v := range vs {
					verifyCh <- v
				}
				atomic.AddInt32(&processedBatches, 1)
			}
		}()
	}

	for i := 0; i < s.verifyWorkers; i++ {
		verifyDone.Add(1)
		go func() {
			defer verifyDone.Done()
			for task := range verifyCh {
				f, ok := s.verifyCandidate(task)
				if ok {
					findingCh <- findingResult{finding: f, groupKey: task.groupKey}
					atomic.AddInt32(&findingCount, 1)
				}
				atomic.AddInt32(&processedVerify, 1)
			}
		}()
	}

	var findings []model.Finding
	hitGroups := map[string]bool{}
	var collectDone sync.WaitGroup
	collectDone.Add(1)
	go func() {
		defer collectDone.Done()
		seen := map[string]struct{}{}
		for fr := range findingCh {
			f := fr.finding
			key := f.URL + "|" + f.Param + "|" + f.Context + "|" + strings.Join(intsToStr(f.ReflectedLines), ",")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
			if s.onFinding != nil {
				s.onFinding(f)
			}
			hitGroups[fr.groupKey] = true
		}
	}()

	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)
	targetDone.Wait()
	close(quickCh)
	quickDone.Wait()
	close(verifyCh)
	verifyDone.Wait()
	close(findingCh)
	collectDone.Wait()

	close(stopProgress)
	fmt.Printf("\r  > phase=%s | targets %d/%d | skip-shape %d | quick %d/%d | params %d | verify %d | findings %d\n",
		label,
		processedTargets,
		int32(len(targets)),
		skippedByShape,
		processedBatches,
		generatedBatches,
		generatedParams,
		processedVerify,
		findingCount,
	)

	return findings, hitGroups
}

func chunkParams(params []string, batchSize int) [][]string {
	if batchSize <= 0 {
		batchSize = 45
	}
	if len(params) == 0 {
		return nil
	}
	out := make([][]string, 0, (len(params)+batchSize-1)/batchSize)
	for i := 0; i < len(params); i += batchSize {
		e := i + batchSize
		if e > len(params) {
			e = len(params)
		}
		out = append(out, params[i:e])
	}
	return out
}

func dedupeFindings(in []model.Finding) []model.Finding {
	bestByKey := map[string]model.Finding{}
	for _, f := range in {
		key := findingDedupKey(f)
		exist, ok := bestByKey[key]
		if !ok {
			bestByKey[key] = f
			continue
		}
		if len(f.Indicator) > len(exist.Indicator) {
			bestByKey[key] = f
		}
	}
	out := make([]model.Finding, 0, len(bestByKey))
	for _, f := range bestByKey {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Param != out[j].Param {
			return out[i].Param < out[j].Param
		}
		return out[i].Context < out[j].Context
	})
	return out
}

func findingDedupKey(f model.Finding) string {
	u, err := url.Parse(f.URL)
	if err != nil {
		return f.URL + "|" + f.Param + "|" + f.Context
	}
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	baseCtx := strings.Split(strings.ToLower(strings.TrimSpace(f.Context)), ":")[0]
	return strings.ToLower(u.Scheme) + "|" + strings.ToLower(u.Hostname()) + "|" + markPath(u.Path) +
		"|" + strings.Join(keys, ",") + "|" + strings.ToLower(strings.TrimSpace(f.Param)) + "|" + baseCtx
}

func templateKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := markPath(u.Path)
	qkeys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		qkeys = append(qkeys, strings.ToLower(k))
	}
	sort.Strings(qkeys)
	return strings.ToLower(u.Hostname()) + "|" + path + "|" + strings.Join(qkeys, ",")
}

func markPath(p string) string {
	p = tplUUIDRe.ReplaceAllString(p, "{uuid}")
	p = tplHexRe.ReplaceAllString(p, "{hex}")
	p = tplNumRe.ReplaceAllString(p, "{n}")
	return p
}

func requestShapeFingerprint(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	keys := make([]string, 0, len(q))
	shapeParts := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	for _, k := range keys {
		shapeParts = append(shapeParts, k+"="+valueShape(q.Get(k)))
	}
	return strings.ToLower(u.Hostname()) + "|" + markPath(u.Path) + "|" + strings.Join(keys, ",") + "|" + strings.Join(shapeParts, ";")
}

func smartRequestFingerprint(rawURL string, batchParams []string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	markedPath := markPath(u.Path)
	query := u.Query()

	// Include existing query keys and current batch keys.
	keySet := map[string]struct{}{}
	shapeByKey := map[string]string{}
	for k := range query {
		nk := normalizeParamKey(k)
		keySet[nk] = struct{}{}
		shapeByKey[nk] = valueShape(query.Get(k))
	}
	for _, k := range batchParams {
		nk := normalizeParamKey(k)
		keySet[nk] = struct{}{}
		if _, ok := shapeByKey[nk]; !ok {
			shapeByKey[nk] = valueShape("xssmarker123")
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Existing query values use real shape; batch params use fixed marker shape.
	shapeItems := make([]string, 0, len(keys))
	for _, k := range keys {
		shapeItems = append(shapeItems, k+"="+shapeByKey[k])
	}

	base := "GET|" + strings.ToLower(u.Scheme) + "|" + strings.ToLower(u.Hostname()) + "|" + markedPath +
		"|" + strings.Join(keys, ",") + "|" + strings.Join(shapeItems, ";")
	sum := md5.Sum([]byte(base))
	return hex.EncodeToString(sum[:])
}

func normalizeParamKey(key string) string {
	key = strings.TrimSpace(strings.ToLower(key))
	if key == "" {
		return key
	}
	if len(key) >= 32 {
		return "{long}"
	}
	return numInKeyRe.ReplaceAllString(key, "{n}")
}

func valueShape(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "EMPTY"
	}
	if len(v) >= 64 {
		return "LONG"
	}
	lv := strings.ToLower(v)
	if lv == "true" || lv == "false" {
		return "BOOL"
	}
	if shapeUUIDRe.MatchString(v) {
		return "UUID"
	}
	if shapeDateRe.MatchString(v) {
		return "DATE"
	}
	if shapeURLEncRe.MatchString(v) {
		return "URLENC"
	}
	if shapeUnicodeRe.MatchString(v) {
		return "UNICODE"
	}
	if shapeHTMLRe.MatchString(v) {
		return "HTML"
	}
	if shapeNumRe.MatchString(v) {
		return "NUM"
	}
	if shapeHexRe.MatchString(v) {
		return "HEX"
	}
	if shapeAlphaRe.MatchString(v) {
		return "ALPHA"
	}
	if shapeAlphaNumRe.MatchString(v) {
		return "ALNUM"
	}
	return "OTHER"
}

func (s *Scanner) prepareParams(target model.ScanTarget) ([]string, bool) {
	_, baseline, ct, err := s.client.Get(target.URL)
	if err != nil || !strings.Contains(strings.ToLower(ct), "text/html") {
		return nil, false
	}

	paramSet := map[string]struct{}{}
	for _, p := range target.Params {
		paramSet[p] = struct{}{}
	}
	for _, p := range s.filterHiddenParams(discoverHiddenParams(baseline), paramSet) {
		paramSet[p] = struct{}{}
	}

	params := make([]string, 0, len(paramSet))
	for p := range paramSet {
		params = append(params, p)
	}
	sort.Strings(params)
	if !s.allParams && s.maxParams > 0 && len(params) > s.maxParams {
		params = params[:s.maxParams]
	}
	return params, len(params) > 0
}

func (s *Scanner) filterHiddenParams(hidden []string, existing map[string]struct{}) []string {
	if len(hidden) == 0 {
		return nil
	}
	if s.paramStrategy != "batch" {
		return util.UniqueStrings(hidden)
	}
	out := make([]string, 0, len(hidden))
	seen := map[string]struct{}{}
	for _, p := range hidden {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		if _, ok := existing[p]; ok {
			continue
		}
		if _, ok := s.highValueParamSet[p]; !ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if s.batchHiddenParamCap > 0 && len(out) >= s.batchHiddenParamCap {
			break
		}
	}
	return out
}

func (s *Scanner) quickReflectBatch(task quickTask) []verifyTask {
	if len(task.params) == 0 {
		return nil
	}
	markers := make(map[string]string, len(task.params))
	paramVals := make(map[string]string, len(task.params))
	for i, p := range task.params {
		m := fmt.Sprintf("x%s_%03d", randHex(2), i)
		markers[p] = m
		paramVals[p] = m
	}

	mutated, err := setQueries(task.baseURL, paramVals)
	if err != nil {
		return nil
	}
	_, reflected, ct, err := s.client.Get(mutated)
	if err != nil || !strings.Contains(strings.ToLower(ct), "text/html") {
		return nil
	}

	out := make([]verifyTask, 0, len(task.params))
	for _, p := range task.params {
		marker := markers[p]
		if !strings.Contains(reflected, marker) {
			continue
		}
		contexts := classifyContexts(reflected, marker)
		if len(contexts) == 0 {
			continue
		}
		findingURL, ferr := setQuery(task.baseURL, p, marker)
		if ferr != nil {
			findingURL = mutated
		}
		out = append(out, verifyTask{
			baseURL:    task.baseURL,
			param:      p,
			marker:     marker,
			contexts:   contexts,
			batchCtx:   paramVals,
			findingURL: findingURL,
			lines:      markerLines(reflected, marker),
			groupKey:   task.groupKey,
		})
	}
	return out
}

func (s *Scanner) verifyCandidate(task verifyTask) (model.Finding, bool) {
	probes := s.selectVerifyProbes(buildSemanticProbes(task.contexts))
	if len(probes) == 0 {
		return model.Finding{}, false
	}

	for _, p := range probes {
		mutatedProbe, err := setQueryWithContext(task.baseURL, task.param, p.Payload, task.batchCtx)
		if err != nil {
			continue
		}
		_, probeResp, probeCT, probeErr := s.client.Get(mutatedProbe)
		if probeErr != nil || !strings.Contains(strings.ToLower(probeCT), "text/html") {
			continue
		}
		ok, reason := semanticEvidence(p, probeResp)
		if !ok {
			continue
		}
		lines := markerLines(probeResp, p.Token)
		if len(lines) == 0 {
			lines = markerLines(probeResp, p.Payload)
		}
		indicator := p.Indicator
		if strings.TrimSpace(reason) != "" {
			indicator = reason
		}
		return model.Finding{
			URL:             mutatedProbe,
			Param:           task.param,
			InjectedValue:   p.Payload,
			Context:         p.Context,
			ReflectedLines:  lines,
			Indicator:       indicator,
			SuggestedAction: "Manual verify with controlled payloads in authorized environment.",
		}, true
	}

	return model.Finding{}, false
}

func (s *Scanner) selectVerifyProbes(probes []semanticProbe) []semanticProbe {
	if len(probes) == 0 {
		return nil
	}
	if s.paramStrategy != "batch" {
		return probes
	}
	out := make([]semanticProbe, 0, len(probes))
	seenCtx := map[string]struct{}{}
	for _, p := range probes {
		ctxKey := verifyContextKey(p.Context)
		if _, ok := seenCtx[ctxKey]; ok {
			continue
		}
		seenCtx[ctxKey] = struct{}{}
		out = append(out, p)
		if s.batchVerifyProbeCap > 0 && len(out) >= s.batchVerifyProbeCap {
			break
		}
	}
	return out
}

func verifyContextKey(ctx string) string {
	if i := strings.IndexByte(ctx, ':'); i > 0 {
		return ctx[:i]
	}
	return ctx
}

func buildSemanticProbes(contexts []string) []semanticProbe {
	token := "xctx" + randAlpha(6)
	seen := map[string]struct{}{}
	var out []semanticProbe
	add := func(p semanticProbe) {
		key := p.Context + "|" + p.Payload
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}

	for _, ctx := range contexts {
		switch ctx {
		case "script":
			add(semanticProbe{
				Context:   "script:string_break",
				Payload:   `";` + token + `;//`,
				Token:     token,
				Indicator: "script string context shows quote-break and statement-injection signs",
			})
			add(semanticProbe{
				Context:   "script:string_break",
				Payload:   `';` + token + `;//`,
				Token:     token,
				Indicator: "script single-quoted string appears breakable and injectable",
			})
			add(semanticProbe{
				Context:   "script:line_comment",
				Payload:   "\n;" + token + ";//",
				Token:     token,
				Indicator: "script line comment appears escapable by newline",
			})
			add(semanticProbe{
				Context:   "script:block_comment",
				Payload:   "*/" + token + ";/*",
				Token:     token,
				Indicator: "script block comment appears closable and escapable",
			})
			add(semanticProbe{
				Context:   "script:identifier",
				Payload:   token,
				Token:     token,
				Indicator: "script identifier position appears controllable",
			})
		case "attribute_value":
			add(semanticProbe{
				Context:   "attribute_value:key",
				Payload:   `"` + token + `="`,
				Token:     token,
				Indicator: "attribute context reflects quote-break marker as attribute key",
			})
			add(semanticProbe{
				Context:   "attribute_value:key",
				Payload:   `'` + token + `='`,
				Token:     token,
				Indicator: "attribute context reflects single-quote break marker",
			})
			add(semanticProbe{
				Context:   "attribute_value:special_attr",
				Payload:   `javascript:` + token + `(1)`,
				Token:     token,
				Indicator: "special URL attribute may accept javascript scheme",
			})
			add(semanticProbe{
				Context:   "attribute_value:special_attr",
				Payload:   `expression(` + token + `)`,
				Token:     token,
				Indicator: "style attribute may allow expression-like payload",
			})
			add(semanticProbe{
				Context:   "attribute_value:event_attr",
				Payload:   `"` + ` onmouseover="` + token + `"`,
				Token:     token,
				Indicator: "attribute breakout may inject event handler",
			})
		case "html_text":
			add(semanticProbe{
				Context:   "html_text",
				Payload:   "<" + token + ">",
				Token:     token,
				Indicator: "html text context reflects new tag marker",
			})
			add(semanticProbe{
				Context:   "html_text",
				Payload:   "</x><" + token + ">",
				Token:     token,
				Indicator: "html text context allows closing and injecting new tag",
			})
		case "comment":
			add(semanticProbe{
				Context:   "comment",
				Payload:   "--><" + token + ">",
				Token:     token,
				Indicator: "comment context reflects comment-close plus tag marker",
			})
		}
	}
	return out
}

func semanticMatch(p semanticProbe, resp string) bool {
	ok, _ := semanticEvidence(p, resp)
	return ok
}

func semanticEvidence(p semanticProbe, resp string) (bool, string) {
	switch p.Context {
	case "script:string_break", "script:line_comment", "script:block_comment", "script:identifier":
		return matchScriptContext(p, resp)
	case "attribute_value:key":
		if rawInAttribute(resp, p.Payload) {
			return true, "attribute value can be broken and a new attribute key is reflected"
		}
		attrKey := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(p.Token) + `\s*=`)
		if attrKey.MatchString(resp) {
			return true, "attribute key appears controllable in response"
		}
		return false, ""
	case "attribute_value:special_attr":
		if matchSpecialAttributeValue(resp, p.Token) {
			return true, "special attribute value looks controllable (javascript/style expression)"
		}
		return false, ""
	case "attribute_value:event_attr":
		eventAttr := regexp.MustCompile(`(?is)\bon[a-z0-9_]+\s*=\s*["'][^"']*` + regexp.QuoteMeta(p.Token) + `[^"']*["']`)
		if eventAttr.MatchString(resp) {
			return true, "event handler attribute appears injected"
		}
		return false, ""
	case "html_text":
		if containsTag(resp, p.Token) {
			return true, "html text context allows new tag-like reflection"
		}
		return false, ""
	case "comment":
		if strings.Contains(resp, p.Payload) || containsTag(resp, p.Token) {
			return true, "html comment context can be closed and reflected"
		}
		return false, ""
	default:
		if strings.Contains(resp, p.Payload) || strings.Contains(resp, p.Token) {
			return true, "generic reflection observed"
		}
		return false, ""
	}
}

func containsTag(resp, token string) bool {
	low := strings.ToLower(resp)
	t := strings.ToLower(token)
	return strings.Contains(low, "<"+t+">") || strings.Contains(low, "<"+t+" ")
}

func matchSpecialAttributeValue(resp, token string) bool {
	jsURL := regexp.MustCompile(`(?is)\b(?:href|src|action|data|srcdoc)\s*=\s*["'][^"']*javascript:[^"']*` + regexp.QuoteMeta(token) + `[^"']*["']`)
	if jsURL.MatchString(resp) {
		return true
	}
	styleExpr := regexp.MustCompile(`(?is)\bstyle\s*=\s*["'][^"']*expression\s*\([^"']*` + regexp.QuoteMeta(token) + `[^"']*\)[^"']*["']`)
	return styleExpr.MatchString(resp)
}

func matchScriptContext(p semanticProbe, resp string) (bool, string) {
	blocks := scriptBlockFind.FindAllStringSubmatch(resp, -1)
	if len(blocks) == 0 {
		return false, ""
	}
	for _, m := range blocks {
		if len(m) < 2 {
			continue
		}
		code := m[1]
		if !strings.Contains(code, p.Token) && !strings.Contains(code, p.Payload) {
			continue
		}
		switch p.Context {
		case "script:string_break":
			if strings.Contains(code, p.Payload) {
				idRe := regexp.MustCompile(`(?m)[;(\s]` + regexp.QuoteMeta(p.Token) + `\s*;`)
				if idRe.MatchString(code) {
					return true, "script string is closed and reflected in executable statement position"
				}
				return true, "script string appears breakable and should be reviewed manually"
			}
		case "script:line_comment":
			if strings.Contains(code, p.Payload) || strings.Contains(code, "\n;"+p.Token+";//") {
				return true, "script line comment appears escapable by newline"
			}
		case "script:block_comment":
			if strings.Contains(code, p.Payload) || strings.Contains(code, "*/"+p.Token+";/*") {
				return true, "script block comment appears closable and escapable"
			}
		case "script:identifier":
			idRe := regexp.MustCompile(`(?m)(^|[^\w$])` + regexp.QuoteMeta(p.Token) + `([^\w$]|$)`)
			if idRe.MatchString(code) {
				return true, "script identifier position appears controllable"
			}
		}
	}
	return false, ""
}

func needsVerify(contexts []string) bool {
	return len(contexts) > 0
}

func discoverHiddenParams(html string) []string {
	set := map[string]struct{}{}
	for _, m := range inputNameRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			set[strings.ToLower(m[1])] = struct{}{}
		}
	}
	for _, m := range jsVarRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 && len(m[1]) <= 24 {
			set[strings.ToLower(m[1])] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func classifyContexts(body, marker string) []string {
	set := map[string]struct{}{}
	script := regexp.MustCompile(fmt.Sprintf(scriptTagRe.String(), regexp.QuoteMeta(marker)))
	if script.MatchString(body) {
		set["script"] = struct{}{}
	}
	attr := regexp.MustCompile(fmt.Sprintf(attrValRe.String(), regexp.QuoteMeta(marker)))
	if attr.MatchString(body) {
		set["attribute_value"] = struct{}{}
	}
	comment := regexp.MustCompile(fmt.Sprintf(commentRe.String(), regexp.QuoteMeta(marker)))
	if comment.MatchString(body) {
		set["comment"] = struct{}{}
	}
	if len(set) == 0 && strings.Contains(body, marker) {
		set["html_text"] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func evaluateEvidence(contexts []string, probe, probeResp string) (evidence, bool) {
	var candidates []evidence
	for _, ctx := range contexts {
		switch ctx {
		case "script":
			if rawInScript(probeResp, probe) {
				candidates = append(candidates, evidence{Context: "script", Indicator: "raw special chars reflected inside script context"})
			}
		case "attribute_value":
			if rawInAttribute(probeResp, probe) {
				candidates = append(candidates, evidence{Context: "attribute_value", Indicator: "raw quote-sensitive chars reflected in attribute value"})
			}
		case "html_text":
			if rawInHTMLText(probeResp, probe) {
				candidates = append(candidates, evidence{Context: "html_text", Indicator: "raw angle brackets reflected in HTML text"})
			}
		case "comment":
			if strings.Contains(probeResp, probe) {
				candidates = append(candidates, evidence{Context: "comment", Indicator: "raw special chars reflected in HTML comment"})
			}
		}
	}
	if len(candidates) == 0 {
		return evidence{}, false
	}
	return candidates[0], true
}

func rawInScript(resp, probe string) bool {
	scriptProbe := regexp.MustCompile(fmt.Sprintf(scriptTagRe.String(), regexp.QuoteMeta(probe)))
	return scriptProbe.MatchString(resp)
}

func rawInAttribute(resp, probe string) bool {
	attrProbe := regexp.MustCompile(fmt.Sprintf(attrValRe.String(), regexp.QuoteMeta(probe)))
	return attrProbe.MatchString(resp)
}

func rawInHTMLText(resp, probe string) bool {
	if !strings.Contains(resp, probe) {
		return false
	}
	return strings.Contains(probe, "<") && strings.Contains(probe, ">")
}

func markerLines(text, marker string) []int {
	lines := strings.Split(text, "\n")
	var out []int
	for i, line := range lines {
		if strings.Contains(line, marker) {
			out = append(out, i+1)
		}
	}
	return out
}

func setQuery(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return util.CanonicalURL(u.String())
}

func setQueryWithContext(rawURL, key, value string, ctx map[string]string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range ctx {
		q.Set(k, v)
	}
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return util.CanonicalURL(u.String())
}

func setQueries(rawURL string, kv map[string]string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range kv {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return util.CanonicalURL(u.String())
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "abcd"
	}
	return hex.EncodeToString(b)
}

func randAlpha(n int) string {
	if n <= 0 {
		return "abc"
	}
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "abcdef"
	}
	for i := range b {
		b[i] = letters[int(raw[i])%len(letters)]
	}
	return string(b)
}

func intsToStr(in []int) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, fmt.Sprintf("%d", v))
	}
	return out
}
