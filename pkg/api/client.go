package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	clientMaxBackoff = 30
	clientMinBackoff = 1
	clientMaxRetries = 4
)

// DefaultMaxResponseBytes bounds decoded API responses to eight MiB.
const DefaultMaxResponseBytes int64 = 8 << 20

// ErrResponseTooLarge identifies an API response exceeding its configured limit.
var ErrResponseTooLarge = errors.New("API response exceeds configured limit")

var clientMutexKey = "OPNSENSE"

type Client struct {
	client *retryablehttp.Client
	opts   Options
}

type Options struct {
	Uri           string
	APIKey        string
	APISecret     string
	AllowInsecure bool

	// Retries
	MaxBackoff int64
	MinBackoff int64
	MaxRetries int64

	Logger *log.Logger

	// HTTPClient supplies transport, TLS trust, timeout, and redirect policy.
	HTTPClient *http.Client
	// MaxResponseBytes limits response bodies; zero selects the default limit.
	MaxResponseBytes int64
	// SuppressBodyLogging keeps request/response payloads out of debug logs.
	SuppressBodyLogging bool
	// DisableRetries delegates retry policy to the caller, including writes.
	DisableRetries bool
}

func NewClient(options Options) *Client {
	httpClient := retryablehttp.NewClient()
	if options.Logger != nil {
		httpClient.Logger = options.Logger
	}
	client := &Client{
		client: httpClient,
		opts:   options,
	}

	// Configure HTTP client
	if options.HTTPClient != nil {
		client.client.HTTPClient = options.HTTPClient
	} else {
		client.client.HTTPClient.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: options.AllowInsecure},
		}
	}

	//   Set defaults for retries
	client.client.RetryWaitMax = clientMaxBackoff
	client.client.RetryWaitMin = clientMinBackoff
	client.client.RetryMax = clientMaxRetries

	//   Override defaults for retries, if set
	if options.MaxBackoff != 0 {
		client.client.RetryWaitMax = time.Duration(options.MaxBackoff) * time.Second
	}
	if options.MinBackoff != 0 {
		client.client.RetryWaitMin = time.Duration(options.MinBackoff) * time.Second
	}
	if options.MaxRetries != 0 {
		client.client.RetryMax = int(options.MaxRetries)
	}
	if options.DisableRetries {
		client.client.RetryMax = 0
	}

	return client
}

// Requests

func (c *Client) getAuth() string {
	auth := c.opts.APIKey + ":" + c.opts.APISecret
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *Client) doRequest(ctx context.Context, method, endpoint string, body any, resp any) error {

	// set logger
	var logger *log.Logger
	if c.opts.Logger != nil {
		logger = c.opts.Logger
	} else {
		logger = log.Default()
	}

	// Create IO readers
	var bodyReader io.Reader
	if body != nil {
		// Marshal body into bytes
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return err
		}

		// Convert body bytes into reader
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create request
	req, err := retryablehttp.NewRequestWithContext(ctx, method, fmt.Sprintf("%s/api%s", c.opts.Uri, endpoint), bodyReader)
	if err != nil {
		return err
	}

	// Add headers
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", c.getAuth()))
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	// Log request
	reqCopy := req.Clone(req.Context())
	reqCopy.Header.Set("Authorization", "****************")

	dReq, _ := httputil.DumpRequest(reqCopy, !c.opts.SuppressBodyLogging)
	logger.Printf("\n%s\n", dReq)

	// Do request
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }() // Cleanup after bounded response consumption.
	limit := c.opts.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("%w: %d bytes", ErrResponseTooLarge, limit)
	}

	// Log response
	resCopy := *res
	resCopy.Body = io.NopCloser(bytes.NewReader(data))
	dRes, _ := httputil.DumpResponse(&resCopy, !c.opts.SuppressBodyLogging)
	logger.Println(ctx, fmt.Sprintf("\n%s\n", string(dRes)))

	// Check for 200
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status code non-200; status code %d", res.StatusCode)
	}

	// Unmarshal resp JSON data to struct
	err = json.Unmarshal(data, resp)
	if err != nil {
		return err
	}

	return nil
}

// ReconfigureService defined at the endpoint.
func (c *Client) ReconfigureService(ctx context.Context, endpoint string) error {
	// Handle services without a reconfigure endpoint
	if endpoint == "" {
		return nil
	}

	// Send reconfigure request to OPNsense
	respJson := &struct {
		Status string `json:"status,omitempty"`
		Result string `json:"result,omitempty"`
	}{}
	err := c.doRequest(ctx, "POST", endpoint, nil, respJson)
	if err != nil {
		return err
	}

	// Since os-wireguard's reconfigure returns {"result":"ok"}, handle both cases
	status := ""
	if respJson.Status != "" {
		status = respJson.Status
	} else if respJson.Result != "" {
		status = respJson.Result
	} else {
		return errors.New("reconfigure returned with unknown status response")
	}

	// Validate service restarted correctly
	status = cases.Lower(language.English).String(
		strings.TrimSpace(status),
	)
	if status != "ok" {
		return fmt.Errorf("reconfigure failed. status: %s", status)
	}

	return nil
}
