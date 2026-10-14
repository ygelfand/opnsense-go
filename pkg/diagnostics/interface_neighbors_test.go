package diagnostics_test

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/browningluke/opnsense-go/pkg/api"
	"github.com/browningluke/opnsense-go/pkg/diagnostics"
	"github.com/browningluke/opnsense-go/pkg/opnsense"
)

// Synthetic API samples exercise documented neighbor-table fields; they are
// not captures from a live OPNsense appliance.
func TestInterfaceGetARP(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		resolve *string
		query   string
	}{
		{name: "default"},
		{name: "resolve names", resolve: stringPointer("yes"), query: "resolve=yes"},
		{name: "disable resolution", resolve: stringPointer("no"), query: "resolve=no"},
		{name: "escaped query", resolve: stringPointer("yes&extra=1"), query: "resolve=yes%26extra%3D1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertReadRequest(t, r, "/api/diagnostics/interface/get_arp", tc.query)
				_, _ = io.WriteString(w, `[{"ip":"192.0.2.10","mac":"02:00:00:00:00:01","manufacturer":"Example Vendor","intf":"igc0","intf_description":"LAN","hostname":"client.example.net"},{"ip":"192.0.2.11","mac":"(incomplete)","intf":"igc0","intf_description":"LAN","hostname":"","manufacturer":""}]`)
			}))
			defer srv.Close()
			entries, err := testController(srv.URL).InterfaceGetARP(testContext(t), tc.resolve)
			if err != nil || entries == nil || len(*entries) != 2 {
				t.Fatalf("InterfaceGetARP() = %v, %v; want two entries", entries, err)
			}
			first := (*entries)[0]
			if first.IP != "192.0.2.10" || first.MAC != "02:00:00:00:00:01" || first.Interface != "igc0" || first.InterfaceDescription != "LAN" || first.Hostname != "client.example.net" || first.Manufacturer != "Example Vendor" {
				t.Errorf("InterfaceGetARP() entry = %+v", first)
			}
			if (*entries)[1].MAC != "(incomplete)" || (*entries)[1].Hostname != "" {
				t.Errorf("incomplete ARP entry = %+v", (*entries)[1])
			}
		})
	}
}

func TestInterfaceGetNDP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertReadRequest(t, r, "/api/diagnostics/interface/get_ndp", "")
		_, _ = io.WriteString(w, `[{"ip":"2001:db8::10","mac":"02:00:00:00:00:01","manufacturer":"Example Vendor","intf":"igc0","intf_description":"LAN"},{"ip":"fe80::10%igc0","mac":"(incomplete)","intf":"igc0","intf_description":"LAN","manufacturer":""}]`)
	}))
	defer srv.Close()
	entries, err := testController(srv.URL).InterfaceGetNDP(testContext(t))
	if err != nil || entries == nil || len(*entries) != 2 {
		t.Fatalf("InterfaceGetNDP() = %v, %v; want two entries", entries, err)
	}
	first := (*entries)[0]
	if first.IP != "2001:db8::10" || first.MAC != "02:00:00:00:00:01" || first.Interface != "igc0" || first.InterfaceDescription != "LAN" || first.Manufacturer != "Example Vendor" {
		t.Errorf("InterfaceGetNDP() entry = %+v", first)
	}
	if (*entries)[1].IP != "fe80::10%igc0" || (*entries)[1].MAC != "(incomplete)" {
		t.Errorf("scoped/incomplete NDP entry = %+v", (*entries)[1])
	}
}

func TestNeighborReadEmptyAndErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{name: "empty", body: "[]", status: http.StatusOK},
		{name: "unexpected object", body: "{}", status: http.StatusOK, wantError: true},
		{name: "malformed JSON", body: "[", status: http.StatusOK, wantError: true},
		{name: "authentication failure", body: `{"message":"denied"}`, status: http.StatusUnauthorized, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			controller := testController(srv.URL)
			arp, arpErr := controller.InterfaceGetARP(testContext(t), nil)
			ndp, ndpErr := controller.InterfaceGetNDP(testContext(t))
			if (arpErr != nil) != tc.wantError || (ndpErr != nil) != tc.wantError {
				t.Fatalf("neighbor errors = %v/%v, want error=%v", arpErr, ndpErr, tc.wantError)
			}
			if !tc.wantError && (arp == nil || ndp == nil || len(*arp) != 0 || len(*ndp) != 0) {
				t.Errorf("empty tables = %v/%v, want empty slices", arp, ndp)
			}
		})
	}
}

func TestNeighborReadCancellation(t *testing.T) {
	t.Parallel()
	started, finished := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := testController(srv.URL).InterfaceGetNDP(ctx); result <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("neighbor request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("canceled read error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("neighbor read ignored cancellation")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled neighbor request did not close")
	}
}

func testController(url string) *diagnostics.Controller {
	client := api.NewClient(api.Options{Uri: url, APIKey: "test-key", APISecret: "test-secret", Logger: log.New(io.Discard, "", 0)})
	return opnsense.NewClient(client).Diagnostics()
}

func assertReadRequest(t *testing.T, r *http.Request, path, query string) {
	t.Helper()
	key, secret, ok := r.BasicAuth()
	if !ok || key != "test-key" || secret != "test-secret" {
		t.Error("neighbor request did not use configured authentication")
	}
	if r.Method != http.MethodGet || r.URL.Path != path || r.URL.RawQuery != query {
		t.Errorf("neighbor request = %s %s, want GET %s?%s", r.Method, r.URL.RequestURI(), path, query)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) != 0 {
		t.Errorf("read request body = %q, %v; want empty", body, err)
	}
}

func stringPointer(value string) *string { return &value }

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
