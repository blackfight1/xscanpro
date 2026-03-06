package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"xscanpro/internal/model"
)

type Config struct {
	Enabled    bool
	MaxPerSite int
	QueueSize  int
	TimeoutSec int
	DingTalk   DingTalkConfig
}

type DingTalkConfig struct {
	Webhook string
	Secret  string
}

type Notifier struct {
	enabled bool
	verbose bool

	client *http.Client
	cfg    Config

	mu              sync.Mutex
	sentByHost      map[string]int
	sentKeySet      map[string]struct{}
	droppedCount    int

	ch chan model.Finding
	wg sync.WaitGroup
}

func New(cfg Config, verbose bool) *Notifier {
	n := &Notifier{
		enabled:         cfg.Enabled,
		verbose:         verbose,
		cfg:             cfg,
		sentByHost:      map[string]int{},
		sentKeySet:      map[string]struct{}{},
	}
	if !cfg.Enabled {
		return n
	}

	if cfg.MaxPerSite <= 0 {
		cfg.MaxPerSite = 10
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 200
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 8
	}
	n.cfg = cfg

	n.client = &http.Client{Timeout: time.Duration(cfg.TimeoutSec) * time.Second}
	n.ch = make(chan model.Finding, cfg.QueueSize)
	n.wg.Add(1)
	go n.loop()
	return n
}

func (n *Notifier) EnqueueFinding(f model.Finding) {
	if !n.enabled {
		return
	}
	select {
	case n.ch <- f:
	default:
		n.mu.Lock()
		n.droppedCount++
		n.mu.Unlock()
	}
}

func (n *Notifier) Close() {
	if !n.enabled {
		return
	}
	close(n.ch)
	n.wg.Wait()
	if n.verbose {
		n.mu.Lock()
		dropped := n.droppedCount
		n.mu.Unlock()
		fmt.Printf("      notify summary: queue_dropped=%d\n", dropped)
	}
}

func (n *Notifier) loop() {
	defer n.wg.Done()
	for f := range n.ch {
		host := hostOf(f.URL)
		if host == "" {
			host = "unknown"
		}
		if !n.reserveSend(host, f) {
			continue
		}
		if err := n.sendDingTalk(f, host); err != nil {
			n.releaseSend(host, f)
			if n.verbose {
				fmt.Printf("      notify warning: %v\n", err)
			}
		}
	}
}

func (n *Notifier) reserveSend(host string, f model.Finding) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.sentByHost[host] >= n.cfg.MaxPerSite {
		return false
	}

	param := strings.ToLower(strings.TrimSpace(f.Param))
	if param == "" {
		param = "{empty}"
	}
	path := pathOf(f.URL)
	ctx := strings.ToLower(strings.TrimSpace(f.Context))
	uniq := host + "|" + path + "|" + param + "|" + ctx
	if _, exists := n.sentKeySet[uniq]; exists {
		return false
	}

	n.sentByHost[host]++
	n.sentKeySet[uniq] = struct{}{}
	return true
}

func (n *Notifier) releaseSend(host string, f model.Finding) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.sentByHost[host] > 0 {
		n.sentByHost[host]--
	}
	param := strings.ToLower(strings.TrimSpace(f.Param))
	if param == "" {
		param = "{empty}"
	}
	path := pathOf(f.URL)
	ctx := strings.ToLower(strings.TrimSpace(f.Context))
	uniq := host + "|" + path + "|" + param + "|" + ctx
	delete(n.sentKeySet, uniq)
}

func (n *Notifier) sendDingTalk(f model.Finding, host string) error {
	webhook := strings.TrimSpace(n.cfg.DingTalk.Webhook)
	if webhook == "" {
		return fmt.Errorf("dingtalk webhook is empty")
	}
	finalURL := webhook
	if strings.TrimSpace(n.cfg.DingTalk.Secret) != "" {
		ts := time.Now().UnixMilli()
		sign := dingTalkSign(ts, n.cfg.DingTalk.Secret)
		sep := "?"
		if strings.Contains(webhook, "?") {
			sep = "&"
		}
		finalURL = fmt.Sprintf("%s%stimestamp=%d&sign=%s", webhook, sep, ts, url.QueryEscape(sign))
	}

	title := fmt.Sprintf("[XSS] %s", host)
	content := fmt.Sprintf(
		"### %s\n- URL: `%s`\n- Param: `%s`\n- Payload: `%s`\n- Context: `%s`\n- Evidence: %s\n",
		title,
		strings.TrimSpace(f.URL),
		f.Param,
		trimText(f.InjectedValue, 500),
		f.Context,
		trimText(f.Indicator, 500),
	)
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			"text":  content,
		},
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, finalURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("dingtalk status: %d", resp.StatusCode)
	}
	return nil
}

func dingTalkSign(timestamp int64, secret string) string {
	raw := fmt.Sprintf("%d\n%s", timestamp, secret)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(raw))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.TrimSpace(rawURL)
	}
	p := strings.TrimSpace(u.Path)
	if p == "" {
		p = "/"
	}
	return p
}

func trimText(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
