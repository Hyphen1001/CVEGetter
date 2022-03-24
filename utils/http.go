package utils

import (
	"edu.buaa.soft/CVEGetter/config"
	"edu.buaa.soft/CVEGetter/utils/pool"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/juju/errors"
)

var (
	httpClient = &http.Client{}
	timeLock   = sync.Mutex{}
)

// GitRateLimit 限速是为了确保每小时访问git API次数不超过5000
func GitRateLimit() {
	timeLock.Lock()
	time.Sleep(time.Duration(config.LoadConfig().GitAPIRateLimit) * time.Millisecond)
	timeLock.Unlock()
}

func SimpleRequest(url, method string) (*http.Response, error) {
	GitRateLimit()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.Trace(err)
	}
	req.Header.Add("Content-Type", "application/vnd.github.v3+json")
	req.Header.Add("Authorization", "bearer "+pool.GetToken())

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return res, nil
}

func RequestWithGitToken(url, payload, method string) (*http.Response, error) {
	GitRateLimit()
	req, err := http.NewRequest(method, url,
		strings.NewReader(payload))
	if err != nil {
		return nil, errors.Trace(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "bearer "+pool.GetToken())

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return res, nil
}

func RequestWithGitAuth(url, payload, method string) (*http.Response, error) {
	GitRateLimit()
	req, err := http.NewRequest(method, url,
		strings.NewReader(payload))
	if err != nil {
		return nil, errors.Trace(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Token "+pool.GetToken())

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return res, nil
}

func RequestWithQueryParams(url, payload, method string, params map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url,
		strings.NewReader(payload))
	if err != nil {
		return nil, errors.Trace(err)
	}
	req.Header.Add("Content-Type", "application/vnd.github.v3+json")
	req.Header.Add("Authorization", "Token "+pool.GetToken())
	query := req.URL.Query()
	for key, value := range params {
		query.Add(key, value)
	}
	req.URL.RawQuery = query.Encode()

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return res, nil
}
