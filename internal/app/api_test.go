package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func newTestApp(t *testing.T) *App {
	a, _ := newTestAppWithPihole(t)
	return a
}

func newTestAppWithPihole(t *testing.T) (*App, *fakePihole) {
	t.Helper()
	f := newFakePihole(t)
	t.Setenv("LIMITED_CLIENTS", "100.100.232.87,100.81.231.4")
	t.Setenv("DAYLY_WATCHING_LIMIT", "1h30m")
	t.Setenv("TRACKED_DOMAINS", "*youtube*,*.ytimg.com")
	return NewApp(), f
}

func post(h http.HandlerFunc, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, nil))
	return rec
}

func TestBlockThenResetRoundTrip(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	setClientName(&a.stats, "100.81.231.4", "redmi-tv")

	if rec := post(a.handleBlock, "/block?ip=100.81.231.4"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "redmi-tv blocked") {
		t.Fatalf("block: %d %q", rec.Code, rec.Body)
	}
	gid := f.groups["ParentalControl-100.81.231.4"]
	if !slices.Contains(f.clients["100.81.231.4"], gid) || !slices.Contains(f.domains[`^.*youtube.*$`], gid) || !slices.Contains(f.domains[`^.*\.ytimg\.com$`], gid) {
		t.Fatalf("pihole state after block: groups=%v clients=%v domains=%v", f.groups, f.clients, f.domains)
	}
	if !findClient(&a.stats, "100.81.231.4").Blocked {
		t.Fatal("client not marked blocked")
	}

	if rec := post(a.handleReset, "/reset?ip=100.81.231.4"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unblocked") {
		t.Fatalf("reset: %d %q", rec.Code, rec.Body)
	}
	if slices.Contains(f.clients["100.81.231.4"], gid) || findClient(&a.stats, "100.81.231.4").Blocked {
		t.Fatalf("still blocked after reset: clients=%v", f.clients)
	}
}

func TestSecondDeviceSharesDenyRules(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	for _, ip := range []string{"100.81.231.4", "100.100.232.87"} {
		if rec := post(a.handleBlock, "/block?ip="+ip); rec.Code != http.StatusOK {
			t.Fatalf("block %s: %d %q", ip, rec.Code, rec.Body)
		}
	}
	got := f.domains[`^.*youtube.*$`]
	for _, name := range []string{"ParentalControl-100.81.231.4", "ParentalControl-100.100.232.87"} {
		if !slices.Contains(got, f.groups[name]) {
			t.Errorf("rule groups %v missing %s", got, name)
		}
	}
}

func TestResetUnblocksDeviceThisAppForgot(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	post(a.handleBlock, "/block?ip=100.81.231.4")
	// Simulates a restart: memory lost the flag, Pi-hole still blocks.
	findClient(&a.stats, "100.81.231.4").Blocked = false

	post(a.handleReset, "/reset?ip=100.81.231.4")
	if slices.Contains(f.clients["100.81.231.4"], f.groups["ParentalControl-100.81.231.4"]) {
		t.Fatal("reset left the device blocked in Pi-hole")
	}
}

func TestSyncBlockedRestoresStateAfterRestart(t *testing.T) {
	a, _ := newTestAppWithPihole(t)
	post(a.handleBlock, "/block?ip=100.81.231.4")
	findClient(&a.stats, "100.81.231.4").Blocked = false

	a.syncBlocked()
	if !findClient(&a.stats, "100.81.231.4").Blocked || findClient(&a.stats, "100.100.232.87").Blocked {
		t.Error("syncBlocked did not mirror Pi-hole state")
	}
}

func TestMidnightUnblocksDeviceThisAppForgot(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	post(a.handleBlock, "/block?ip=100.81.231.4")
	findClient(&a.stats, "100.81.231.4").Blocked = false

	if !a.unblockAll() {
		t.Fatal("unblockAll reported failure")
	}
	if slices.Contains(f.clients["100.81.231.4"], f.groups["ParentalControl-100.81.231.4"]) {
		t.Error("midnight unblock skipped a device blocked before restart")
	}
}

func TestPiholeAuthFailureReturns502(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	f.failAuth = true
	if rec := post(a.handleBlock, "/block?ip=100.81.231.4"); rec.Code != http.StatusBadGateway {
		t.Errorf("block with bad Pi-hole password: %d %q", rec.Code, rec.Body)
	}
}

func TestPiholeFailureReturns502(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	f.fail = true
	for path, h := range map[string]http.HandlerFunc{"/block": a.handleBlock, "/reset": a.handleReset} {
		rec := post(h, path+"?ip=100.81.231.4")
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Try again in a minute") || strings.Contains(rec.Body.String(), "Pi-hole") {
			t.Errorf("%s: %d %q", path, rec.Code, rec.Body)
		}
	}
	if findClient(&a.stats, "100.81.231.4").Blocked {
		t.Error("failed block marked the device blocked")
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	t.Setenv("UI_PASSWORD", "s3cret")
	a := newTestApp(t)
	h := a.protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	try := func(pass string) int {
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		req.SetBasicAuth("admin", pass)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < maxFailures; i++ {
		if code := try("nope"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := try("s3cret"); code != http.StatusTooManyRequests {
		t.Errorf("after lockout: %d, want 429", code)
	}
}

func TestNewAppSeedsLimitedClients(t *testing.T) {
	a := newTestApp(t)

	if len(a.stats.Clients) != 2 {
		t.Fatalf("expected 2 seeded clients, got %d", len(a.stats.Clients))
	}
	for _, c := range a.stats.Clients {
		if !c.Limited {
			t.Errorf("seeded client %s should be marked limited", c.IP)
		}
	}
	if a.stats.DailyLimit != 90*time.Minute {
		t.Errorf("DailyLimit = %v, want 1h30m", a.stats.DailyLimit)
	}
}

func TestResetNeverBlockedClientWritesNothing(t *testing.T) {
	a, f := newTestAppWithPihole(t)
	c := findClient(&a.stats, "100.100.232.87")
	c.TimeWatchedToday = 40 * time.Minute

	rec := post(a.handleReset, "/reset?ip=100.100.232.87")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if c.TimeWatchedToday != 0 {
		t.Errorf("time not reset: %v", c.TimeWatchedToday)
	}
	if f.writes != 0 {
		t.Errorf("Pi-hole got %d writes for a device it never blocked", f.writes)
	}
}

func TestResetMessageDoesNotClaimUnblock(t *testing.T) {
	a := newTestApp(t)
	setClientName(&a.stats, "100.81.231.4", "redmi-tv")

	rec := httptest.NewRecorder()
	a.handleReset(rec, httptest.NewRequest(http.MethodPost, "/reset?ip=100.81.231.4", nil))

	body := rec.Body.String()
	if strings.Contains(body, "unblocked") || !strings.Contains(body, "redmi-tv time reset") {
		t.Errorf("unexpected reset message: %q", body)
	}
}

func TestActionsRejectUnknownAndEmptyIP(t *testing.T) {
	a := newTestApp(t)
	handlers := map[string]http.HandlerFunc{"/reset": a.handleReset, "/block": a.handleBlock}
	for path, handler := range handlers {
		for query, want := range map[string]int{"?ip=10.0.0.9": http.StatusNotFound, "": http.StatusBadRequest, "?ip=../groups": http.StatusBadRequest} {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodPost, path+query, nil))
			if rec.Code != want {
				t.Errorf("%s%s: status = %d, want %d", path, query, rec.Code, want)
			}
			if !strings.Contains(rec.Body.String(), "Device not found") {
				t.Errorf("%s%s: body = %q", path, query, rec.Body)
			}
		}
	}
}

func TestActionsRejectGet(t *testing.T) {
	a := newTestApp(t)
	for path, handler := range map[string]http.HandlerFunc{"/reset": a.handleReset, "/block": a.handleBlock} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, path+"?ip=100.100.232.87", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", path, rec.Code)
		}
	}
}

func TestStatsExposesLimitAndFlags(t *testing.T) {
	a := newTestApp(t)
	rec := httptest.NewRecorder()
	a.handleStats(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

	var got struct {
		DailyLimit time.Duration `json:"daily_limit_ns"`
		Clients    []struct {
			IP      string `json:"ip"`
			Limited bool   `json:"limited"`
		} `json:"clients"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.DailyLimit != 90*time.Minute || len(got.Clients) != 2 || !got.Clients[0].Limited {
		t.Errorf("unexpected stats: %+v", got)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestStaticFilesServed(t *testing.T) {
	a := newTestApp(t)
	h := a.routes()
	for path, want := range map[string]string{
		"/":            "<title>Parental Control</title>",
		"/app.js":      "async function load(",
		"/app.css":     "--muted:",
		"/favicon.svg": "<svg",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: status %d, missing %q", path, rec.Code, want)
		}
	}
}

func TestProtect(t *testing.T) {
	t.Setenv("UI_PASSWORD", "s3cret")
	a := newTestApp(t)
	h := a.protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	cases := []struct {
		name, method, pass, origin string
		header                     bool
		want                       int
	}{
		{"no password", http.MethodGet, "", "", false, http.StatusUnauthorized},
		{"wrong password", http.MethodGet, "nope", "", false, http.StatusUnauthorized},
		{"right password", http.MethodGet, "s3cret", "", false, http.StatusOK},
		{"post with header", http.MethodPost, "s3cret", "", true, http.StatusOK},
		{"post without header", http.MethodPost, "s3cret", "", false, http.StatusForbidden},
		{"same-origin http post", http.MethodPost, "s3cret", "http://example.com", true, http.StatusOK},
		{"same-origin https post", http.MethodPost, "s3cret", "https://example.com", true, http.StatusOK},
		{"cross-site post", http.MethodPost, "s3cret", "http://evil.test", true, http.StatusForbidden},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "http://example.com/reset", nil)
		if tc.pass != "" {
			req.SetBasicAuth("admin", tc.pass)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.header {
			req.Header.Set(actionHeader, "1")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestProtectWithoutPasswordIsReadOnly(t *testing.T) {
	t.Setenv("UI_PASSWORD", "")
	a := newTestApp(t)
	h := a.protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if get.Code != http.StatusOK {
		t.Errorf("GET without password: status = %d, want 200", get.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/reset?ip=100.100.232.87", nil)
	req.Header.Set(actionHeader, "1")
	post := httptest.NewRecorder()
	h.ServeHTTP(post, req)
	if post.Code != http.StatusForbidden || post.Body.String() != errReadOnly+"\n" {
		t.Errorf("POST without password: status = %d, body = %q", post.Code, post.Body)
	}

	stats := httptest.NewRecorder()
	a.handleStats(stats, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if !strings.Contains(stats.Body.String(), `"read_only":true`) {
		t.Errorf("stats should flag read-only: %s", stats.Body)
	}
}

func TestProtectSetsSecurityHeaders(t *testing.T) {
	a := newTestApp(t)
	rec := httptest.NewRecorder()
	a.protect(a.routes()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %q", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP still allows inline code: %q", csp)
	}
}

func TestSetClientNameAndFind(t *testing.T) {
	stats := &DomainStats{Clients: []*Client{NewClientStats("100.81.231.4")}}
	setClientName(stats, "100.81.231.4", "redmi-tv.tail1058b4.ts.net")
	setClientName(stats, "10.0.0.1", "ignored")

	if stats.Clients[0].Name != "redmi-tv.tail1058b4.ts.net" {
		t.Errorf("name = %q", stats.Clients[0].Name)
	}
	if !checkIfClientExist(stats, "100.81.231.4") || checkIfClientExist(stats, "10.0.0.1") {
		t.Error("checkIfClientExist wrong")
	}
}
