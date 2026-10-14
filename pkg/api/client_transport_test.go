package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/browningluke/opnsense-go/pkg/api"
	"github.com/browningluke/opnsense-go/pkg/opnsense"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInjectedTransportBodyLoggingAndLimit(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	client := api.NewClient(api.Options{Uri: "https://192.0.2.10", APIKey: "test-key", APISecret: "test-secret", MaxResponseBytes: 64, SuppressBodyLogging: true, DisableRetries: true, Logger: log.New(&logs, "", 0), HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		key, secret, ok := r.BasicAuth()
		if !ok || key != "test-key" || secret != "test-secret" {
			t.Error("injected client lost authentication")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"value":"response-private"}`)), Request: r}, nil
	})}})
	var response struct {
		Value string `json:"value"`
	}
	_, err := api.Call(client, context.Background(), api.RPCOpts{BaseEndpoint: "/test", Method: http.MethodPost, BodyParameters: map[string]any{"private": "request-private"}}, &response)
	if err != nil || response.Value != "response-private" {
		t.Fatalf("injected response = %+v, %v", response, err)
	}
	for _, secret := range []string{"request-private", "response-private", "test-secret"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("suppressed log contains %q", secret)
		}
	}
	large := api.NewClient(api.Options{Uri: "https://192.0.2.10", MaxResponseBytes: 16, DisableRetries: true, Logger: log.New(io.Discard, "", 0), HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 100))), Request: r}, nil
	})}})
	_, err = api.Call(large, context.Background(), api.RPCOpts{BaseEndpoint: "/test", Method: http.MethodGet}, &response)
	if !errors.Is(err, api.ErrResponseTooLarge) {
		t.Errorf("oversized response error = %v", err)
	}
}

func TestReadRPCDoesNotWaitForGlobalWriteLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := api.GlobalMutexKV.Lock("OPNSENSE", ctx); err != nil {
		t.Fatal(err)
	}
	defer api.GlobalMutexKV.Unlock("OPNSENSE", ctx)
	client := api.NewClient(api.Options{Uri: "https://192.0.2.10", DisableRetries: true, Logger: log.New(io.Discard, "", 0), HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	})}})
	var response map[string]any
	if _, err := api.Call(client, ctx, api.RPCOpts{BaseEndpoint: "/test", Method: http.MethodGet}, &response); err != nil {
		t.Errorf("GET waited for write lock: %v", err)
	}
}

func TestDisableRetries(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	client := api.NewClient(api.Options{Uri: "https://192.0.2.10", DisableRetries: true, Logger: log.New(io.Discard, "", 0), HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusBadGateway, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	})}})
	var response map[string]any
	_, err := api.Call(client, context.Background(), api.RPCOpts{BaseEndpoint: "/test", Method: http.MethodGet}, &response)
	if err == nil || calls.Load() != 1 {
		t.Errorf("disabled retries = %d requests, %v", calls.Load(), err)
	}
}

func TestIntegerAPIFields(t *testing.T) {
	t.Parallel()
	for _, data := range []string{`9007199254740993`, `"9007199254740993"`} {
		var v api.Int64
		if err := json.Unmarshal([]byte(data), &v); err != nil || int64(v) != 9007199254740993 {
			t.Errorf("integer %s = %d, %v", data, v, err)
		}
	}
	for _, data := range []string{`1.5`, `"not-an-integer"`, `9223372036854775808`, `null`} {
		var v api.Int64
		if err := json.Unmarshal([]byte(data), &v); err == nil {
			t.Errorf("invalid integer %s accepted", data)
		}
	}
}

func TestTypedLeaseReaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("rowCount") != "-1" || r.URL.Query().Get("current") != "1" {
			t.Errorf("lease query = %s %s", r.Method, r.URL)
		}
		_, _ = io.WriteString(w, `{"total":"1","rows":[{"address":"192.0.2.10","hwaddr":"02:00:00:00:00:01","if":"igc0","hostname":"client","expire":"1800000000","state":0,"lease_type":"static"}]}`)
	}))
	defer srv.Close()
	client := opnsense.NewClient(api.NewClient(api.Options{Uri: srv.URL, HTTPClient: srv.Client(), DisableRetries: true, Logger: log.New(io.Discard, "", 0)}))
	all, page := "-1", "1"
	v4, err := client.Kea().LeasesSearchV4(context.Background(), &all, &page)
	if err != nil || v4.Total == nil || *v4.Total != 1 || len(v4.Rows) != 1 || v4.Rows[0].Expires == nil || *v4.Rows[0].Expires != 1800000000 {
		t.Fatalf("Kea v4 leases = %+v, %v", v4, err)
	}
	if _, err := client.Kea().LeasesSearchV6(context.Background(), &all, &page); err != nil {
		t.Fatal(err)
	}
	dnsmasq, err := client.Dnsmasq().LeasesSearch(context.Background(), &all, &page)
	if err != nil || len(dnsmasq.Rows) != 1 || dnsmasq.Rows[0].MAC != "02:00:00:00:00:01" {
		t.Fatalf("Dnsmasq leases = %+v, %v", dnsmasq, err)
	}
}
