package fetch

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	http *http.Client
}

func New(timeoutSec int) *Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 30,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		http: &http.Client{
			Timeout:   time.Duration(timeoutSec) * time.Second,
			Transport: tr,
		},
	}
}

func (c *Client) Get(url string) (status int, body string, contentType string, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", "xscanpro/0.1")
	req.Header.Set("Accept", "*/*")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", resp.Header.Get("Content-Type"), fmt.Errorf("read body: %w", err)
	}
	return resp.StatusCode, string(raw), resp.Header.Get("Content-Type"), nil
}
