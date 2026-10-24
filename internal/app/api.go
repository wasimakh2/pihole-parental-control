package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"
)

//go:embed web
var webFiles embed.FS

// actionHeader must accompany every POST. Browsers cannot send a custom header
// cross-site without a CORS preflight this server never approves, so a forged
// form or fetch from another page is rejected even with cached credentials.
const actionHeader = "X-Parental-Control"

const (
	errUnknownDevice = "Device not found. Refresh the page and try again."
	errReadOnly      = "View only: blocking and resetting are off until this page has a password. Ask the person who set it up."
	errForeign       = "This request did not come from this page. Reload the page and try again."
	errNoAnswer      = "Could not %s %s right now. Try again in a minute."
)

func (a *App) StartServer() {
	fmt.Printf("Starting API server on port %s\n", a.cfg.ApiPort)
	if a.cfg.UIPassword == "" {
		fmt.Println("WARNING: UI_PASSWORD is not set; the UI is read-only until it is")
	}
	srv := &http.Server{
		Addr:              ":" + a.cfg.ApiPort,
		Handler:           a.protect(a.routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      piholeTimeout + 10*time.Second,
		IdleTimeout:       time.Minute,
	}
	go func() {
		// Exit so the container restarts instead of running with no UI.
		log.Fatalf("API server failed: %v", srv.ListenAndServe())
	}()
}

func (a *App) routes() http.Handler {
	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/reset", a.handleReset)
	mux.HandleFunc("/block", a.handleBlock)
	mux.HandleFunc("/stats", a.handleStats)
	mux.Handle("/", http.FileServerFS(static))
	return mux
}

// protect guards every route: limited devices can reach this server too.
func (a *App) protect(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(a.cfg.UIPassword))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if a.cfg.UIPassword != "" {
			if !a.authOK(w, r, want) {
				return
			}
		}
		if r.Method == http.MethodPost {
			if msg := rejectAction(r, a.cfg.UIPassword != ""); msg != "" {
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) authOK(w http.ResponseWriter, r *http.Request, want [32]byte) bool {
	host := remoteHost(r)
	if a.limiter.blocked(host) {
		http.Error(w, "Too many wrong passwords. Try again later.", http.StatusTooManyRequests)
		return false
	}
	_, pass, ok := r.BasicAuth()
	// Hash both sides so the comparison does not leak the password length.
	got := sha256.Sum256([]byte(pass))
	if ok && subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
		a.limiter.succeed(host)
		return true
	}
	// A browser's first request carries no credentials; only count real guesses.
	if ok {
		a.limiter.fail(host)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="parental-control"`)
	http.Error(w, "Wrong password. Try again.", http.StatusUnauthorized)
	return false
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func setSecurityHeaders(w http.ResponseWriter) {
	// Framed UI would let another page trick a click on Unblock.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// rejectAction returns why a POST must be refused, or "" to allow it.
func rejectAction(r *http.Request, hasPassword bool) string {
	if !hasPassword {
		// Without a password a limited device could unblock itself.
		return errReadOnly
	}
	if r.Header.Get(actionHeader) == "" {
		return errForeign
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host && origin != "https://"+r.Host {
		return errForeign
	}
	return ""
}

func (a *App) handleReset(w http.ResponseWriter, r *http.Request) {
	ip, ok := actionIP(w, r)
	if !ok {
		return
	}
	a.actionMu.Lock()
	defer a.actionMu.Unlock()
	name, wasBlocked, found := a.lookup(ip)
	if !found {
		http.Error(w, errUnknownDevice, http.StatusNotFound)
		return
	}

	// Always ask Pi-hole: after a restart memory says unblocked while Pi-hole may still block.
	ctx, cancel := context.WithTimeout(r.Context(), piholeTimeout)
	defer cancel()
	if err := a.client.UnblockDomainsForClient(ctx, ip); err != nil {
		fmt.Printf("API: Failed to unblock client %s: %v\n", ip, err)
		verb := "reset the time on"
		if wasBlocked {
			verb = "unblock"
		}
		http.Error(w, fmt.Sprintf(errNoAnswer, verb, name), http.StatusBadGateway)
		return
	}

	a.mu.Lock()
	if c := findClient(&a.stats, ip); c != nil {
		resetClientStats(c)
		c.Blocked = false
	}
	a.mu.Unlock()

	if wasBlocked {
		fmt.Fprintf(w, "%s unblocked and time reset to 0.\n", name)
		return
	}
	fmt.Fprintf(w, "%s time reset to 0.\n", name)
}

func (a *App) handleBlock(w http.ResponseWriter, r *http.Request) {
	ip, ok := actionIP(w, r)
	if !ok {
		return
	}
	a.actionMu.Lock()
	defer a.actionMu.Unlock()
	name, _, found := a.lookup(ip)
	if !found {
		http.Error(w, errUnknownDevice, http.StatusNotFound)
		return
	}

	fmt.Printf("API: Blocking client %s\n", ip)
	ctx, cancel := context.WithTimeout(r.Context(), piholeTimeout)
	defer cancel()
	if err := a.client.BlockDomainsForClient(ctx, ip, a.cfg.DomainsToCheck); err != nil {
		fmt.Printf("API: Failed to block client %s: %v\n", ip, err)
		http.Error(w, fmt.Sprintf(errNoAnswer, "block", name), http.StatusBadGateway)
		return
	}

	// Stays blocked until Reset or the midnight unblock.
	a.setBlocked(ip, true)
	fmt.Fprintf(w, "%s blocked until midnight or until you unblock it.\n", name)
}

// actionIP validates the method and ip parameter shared by /block and /reset.
func actionIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	ip := r.URL.Query().Get("ip")
	if net.ParseIP(ip) == nil {
		http.Error(w, errUnknownDevice, http.StatusBadRequest)
		return "", false
	}
	return ip, true
}

func (a *App) lookup(ip string) (name string, blocked, found bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c := findClient(&a.stats, ip)
	if c == nil {
		return "", false, false
	}
	return displayName(c), c.Blocked, true
}

func displayName(c *Client) string {
	if c.Name != "" {
		return c.Name
	}
	return c.IP
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Encode under the lock, write after it, so a slow reader never stalls the poll loop.
	a.mu.RLock()
	body, err := json.Marshal(struct {
		DomainStats
		ReadOnly bool `json:"read_only"`
	}{a.stats, a.cfg.UIPassword == ""})
	a.mu.RUnlock()
	if err != nil {
		fmt.Printf("API: Failed to encode stats: %v\n", err)
		http.Error(w, "Could not load devices.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}
