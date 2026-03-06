package crawler

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"xscanpro/internal/fetch"
	"xscanpro/internal/model"
	"xscanpro/internal/util"
)

var (
	hrefRe   = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"']+)["']`)
	scriptRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	jsExtRe  = regexp.MustCompile(`(?i)\.m?js(?:\?|$)`)
)

type Crawler struct {
	client      *fetch.Client
	domain      string
	maxDepth    int
	maxPages    int
	workerCount int
	verbose     bool
}

type task struct {
	u     string
	depth int
}

func New(client *fetch.Client, domain string, maxDepth, maxPages, workers int, verbose bool) *Crawler {
	return &Crawler{
		client:      client,
		domain:      strings.ToLower(domain),
		maxDepth:    maxDepth,
		maxPages:    maxPages,
		workerCount: workers,
		verbose:     verbose,
	}
}

func (c *Crawler) Crawl(seeds []string) (model.CrawlResult, error) {
	var result model.CrawlResult
	visited := map[string]struct{}{}
	queue := make([]task, 0, len(seeds))

	for _, seed := range seeds {
		norm, err := util.CanonicalURL(seed)
		if err != nil {
			continue
		}
		queue = append(queue, task{u: norm, depth: 0})
	}
	if len(queue) == 0 {
		return result, fmt.Errorf("no valid seeds")
	}

	for len(queue) > 0 && len(visited) < c.maxPages {
		levelDepth := queue[0].depth
		var level []task
		for len(queue) > 0 && queue[0].depth == levelDepth {
			level = append(level, queue[0])
			queue = queue[1:]
		}

		next := c.processLevel(level, visited)
		if levelDepth < c.maxDepth {
			queue = append(queue, next...)
		}
	}

	for u := range visited {
		result.URLs = append(result.URLs, u)
		if jsExtRe.MatchString(u) {
			result.JSURLs = append(result.JSURLs, u)
		}
	}
	result.URLs = util.UniqueStrings(result.URLs)
	result.JSURLs = util.UniqueStrings(result.JSURLs)
	return result, nil
}

func (c *Crawler) processLevel(level []task, visited map[string]struct{}) []task {
	var mu sync.Mutex
	var next []task

	sem := make(chan struct{}, c.workerCount)
	var wg sync.WaitGroup
	for _, t := range level {
		wg.Add(1)
		sem <- struct{}{}
		go func(tt task) {
			defer wg.Done()
			defer func() { <-sem }()

			u, err := url.Parse(tt.u)
			if err != nil || !util.ScopeMatch(u.Hostname(), c.domain) {
				return
			}

			mu.Lock()
			if _, ok := visited[tt.u]; ok {
				mu.Unlock()
				return
			}
			visited[tt.u] = struct{}{}
			mu.Unlock()

			status, body, contentType, err := c.client.Get(tt.u)
			if err != nil || status < 200 || status >= 400 {
				return
			}

			links := extractLinks(tt.u, body)
			if strings.Contains(strings.ToLower(contentType), "javascript") {
				links = append(links, tt.u)
			}

			mu.Lock()
			for _, n := range links {
				nu, err := url.Parse(n)
				if err != nil || !util.ScopeMatch(nu.Hostname(), c.domain) {
					continue
				}
				canon, err := util.CanonicalURL(n)
				if err != nil {
					continue
				}
				if _, ok := visited[canon]; ok {
					continue
				}
				next = append(next, task{u: canon, depth: tt.depth + 1})
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return next
}

func extractLinks(baseURL, body string) []string {
	matches := hrefRe.FindAllStringSubmatch(body, -1)
	smatches := scriptRe.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches)+len(smatches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		if joined, ok := resolveLink(baseURL, m[1]); ok {
			out = append(out, joined)
		}
	}
	for _, m := range smatches {
		if len(m) < 2 {
			continue
		}
		if joined, ok := resolveLink(baseURL, m[1]); ok {
			out = append(out, joined)
		}
	}
	return util.UniqueStrings(out)
}

func resolveLink(base, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "#") {
		return "", false
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	return baseURL.ResolveReference(r).String(), true
}
