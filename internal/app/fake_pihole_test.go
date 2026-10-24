package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakePihole implements the slice of the Pi-hole v6 API the client uses.
type fakePihole struct {
	mu       sync.Mutex
	fail     bool
	failAuth bool
	groups   map[string]int
	domains  map[string][]int // deny regex -> group ids
	clients  map[string][]int // ip -> group ids
	writes   int
	nextID   int
}

func newFakePihole(t *testing.T) *fakePihole {
	t.Helper()
	f := &fakePihole{groups: map[string]int{}, domains: map[string][]int{}, clients: map[string][]int{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	t.Setenv("PIHOLE_ADDRESS", srv.URL)
	return f
}

func (f *fakePihole) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	if path == "/api/auth" {
		if f.failAuth {
			http.Error(w, "wrong password", http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"session": map[string]any{"valid": true, "sid": "sid", "validity": 300}})
		return
	}
	if r.Header.Get("X-FTL-SID") != "sid" {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if f.fail {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	var body struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Client string `json:"client"`
		Groups []int  `json:"groups"`
	}
	if r.Method != http.MethodGet {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if r.Method != http.MethodGet {
		f.writes++
	}

	switch {
	case strings.HasPrefix(path, "/api/groups/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(path, "/api/groups/")
		var out []map[string]any
		if id, ok := f.groups[name]; ok {
			out = append(out, map[string]any{"id": id, "name": name})
		}
		writeJSON(w, map[string]any{"groups": out})
	case path == "/api/groups" && r.Method == http.MethodPost:
		if _, dup := f.groups[body.Name]; dup {
			http.Error(w, "UNIQUE constraint failed", http.StatusBadRequest)
			return
		}
		f.nextID++
		id := f.nextID + 10
		f.groups[body.Name] = id
		writeJSON(w, map[string]any{"groups": []map[string]any{{"id": id, "name": body.Name}}})
	case strings.HasPrefix(path, "/api/domains/deny/regex/") && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		re := strings.TrimPrefix(path, "/api/domains/deny/regex/")
		if r.Method == http.MethodPut {
			f.domains[re] = body.Groups
			writeJSON(w, map[string]any{})
			return
		}
		var out []map[string]any
		if g, ok := f.domains[re]; ok {
			out = append(out, map[string]any{"domain": re, "groups": g, "enabled": true})
		}
		writeJSON(w, map[string]any{"domains": out})
	case path == "/api/domains/deny/regex" && r.Method == http.MethodPost:
		if _, dup := f.domains[body.Domain]; dup {
			http.Error(w, "UNIQUE constraint failed", http.StatusBadRequest)
			return
		}
		f.domains[body.Domain] = body.Groups
		writeJSON(w, map[string]any{})
	case strings.HasPrefix(path, "/api/clients/") && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		ip := strings.TrimPrefix(path, "/api/clients/")
		if r.Method == http.MethodPut {
			f.clients[ip] = body.Groups
			writeJSON(w, map[string]any{})
			return
		}
		var out []map[string]any
		if g, ok := f.clients[ip]; ok {
			out = append(out, map[string]any{"client": ip, "groups": g})
		}
		writeJSON(w, map[string]any{"clients": out})
	case path == "/api/clients" && r.Method == http.MethodPost:
		if _, dup := f.clients[body.Client]; dup {
			http.Error(w, "UNIQUE constraint failed", http.StatusBadRequest)
			return
		}
		f.clients[body.Client] = body.Groups
		writeJSON(w, map[string]any{})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
