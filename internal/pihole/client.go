package pihole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vladikamira/pihole-parental-control/internal/config"
)

func NewClient(config config.Config) *Client {
	return &Client{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type Client struct {
	config            config.Config
	client            *http.Client
	sessionID         string
	sessionExpiration time.Time
	// mu serialises the exported calls: the poll loop and the HTTP handlers
	// share one session and would otherwise race on sessionID.
	mu sync.Mutex
}

func (c *Client) auth(ctx context.Context) error {
	if c.sessionID != "" && time.Now().Before(c.sessionExpiration) {
		return nil
	}

	resp, err := c.send(ctx, http.MethodPost, "/api/auth", map[string]string{"password": c.config.Password})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", resp.Status)
	}

	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return err
	}

	if !authResponse.Session.Valid {
		return fmt.Errorf("session is not valid: %s", authResponse.Session.Message)
	}

	c.sessionID = authResponse.Session.Sid
	c.sessionExpiration = time.Now().Add(time.Duration(authResponse.Session.Validity) * time.Second)

	fmt.Println("Auth succeeded")

	return nil
}

// send builds and runs one API request; body, when non-nil, is sent as JSON.
func (c *Client) send(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.config.PiholeAddress+path, payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.sessionID != "" {
		req.Header.Set("X-FTL-SID", c.sessionID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// Pi-hole dropped the session (restart, timeout); log in again next call.
		c.sessionID = ""
	}
	return resp, nil
}

// call runs a request, fails on any non-2xx status and decodes the reply into out when non-nil.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.send(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) GetDomainStats(ctx context.Context, domain string) (*QueryStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.auth(ctx); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("domain", domain)
	q.Set("from", strconv.FormatInt(time.Now().Add(-c.config.CheckInternal).Unix(), 10))
	q.Set("until", strconv.FormatInt(time.Now().Unix(), 10))

	var stats QueryStats
	if err := c.call(ctx, http.MethodGet, "/api/queries?"+q.Encode(), nil, &stats); err != nil {
		return nil, fmt.Errorf("query stats failed: %w", err)
	}
	return &stats, nil
}

func (c *Client) BlockDomainsForClient(ctx context.Context, clientIP string, domains []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.auth(ctx); err != nil {
		return err
	}

	groupName := groupNameFor(clientIP)
	groupID, err := c.getOrCreateGroup(ctx, groupName)
	if err != nil {
		return fmt.Errorf("failed to get/create group: %w", err)
	}

	for _, domain := range domains {
		if err := c.addDomainToGroup(ctx, GlobToRegex(domain), groupID); err != nil {
			return fmt.Errorf("failed to add domain %s: %w", domain, err)
		}
	}

	if err := c.addClientToGroup(ctx, clientIP, groupID); err != nil {
		return fmt.Errorf("failed to add client to group: %w", err)
	}

	return nil
}

// UnblockDomainsForClient succeeds when the client is already unblocked, so a
// reset works even if this app restarted and forgot the device was blocked.
func (c *Client) UnblockDomainsForClient(ctx context.Context, clientIP string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.auth(ctx); err != nil {
		return err
	}

	groupID, err := c.getGroupID(ctx, groupNameFor(clientIP))
	if errors.Is(err, errNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get group id: %w", err)
	}

	if err := c.removeClientFromGroup(ctx, clientIP, groupID); err != nil {
		return fmt.Errorf("failed to remove client from group: %w", err)
	}

	return nil
}

// IsBlocked reports whether the client is in its parental-control group.
func (c *Client) IsBlocked(ctx context.Context, clientIP string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.auth(ctx); err != nil {
		return false, err
	}
	groupID, err := c.getGroupID(ctx, groupNameFor(clientIP))
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	client, err := c.getClient(ctx, clientIP)
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return slices.Contains(client.Groups, groupID), nil
}

var errNotFound = errors.New("not found")

func groupNameFor(clientIP string) string {
	return "ParentalControl-" + clientIP
}

// GlobToRegex turns a TRACKED_DOMAINS pattern such as "*.ytimg.com" into an
// anchored regex, so dots match only dots and "*" spans any characters.
func GlobToRegex(glob string) string {
	parts := strings.Split(glob, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return "^" + strings.Join(parts, ".*") + "$"
}

func (c *Client) getOrCreateGroup(ctx context.Context, name string) (int, error) {
	id, err := c.getGroupID(ctx, name)
	if !errors.Is(err, errNotFound) {
		return id, err
	}

	var res GroupResponse
	body := map[string]string{"name": name, "description": "Created by Parental Control"}
	if err := c.call(ctx, http.MethodPost, "/api/groups", body, &res); err != nil {
		return 0, fmt.Errorf("failed to create group: %w", err)
	}
	if len(res.Groups) == 0 {
		return c.getGroupID(ctx, name)
	}
	fmt.Printf("Group %s created with id: %d\n", name, res.Groups[0].ID)
	return res.Groups[0].ID, nil
}

func (c *Client) getGroupID(ctx context.Context, name string) (int, error) {
	var groups GroupListResponse
	if err := c.call(ctx, http.MethodGet, "/api/groups/"+url.PathEscape(name), nil, &groups); err != nil {
		return 0, err
	}
	for _, g := range groups.Groups {
		if g.Name == name {
			return g.ID, nil
		}
	}
	return 0, fmt.Errorf("group %s: %w", name, errNotFound)
}

// addDomainToGroup reuses an existing deny rule: one rule serves every
// device's group, and a second POST of the same rule would be rejected.
func (c *Client) addDomainToGroup(ctx context.Context, regex string, groupID int) error {
	path := "/api/domains/deny/regex/" + url.PathEscape(regex)
	var existing struct {
		Domains []DomainItem `json:"domains"`
	}
	if err := c.call(ctx, http.MethodGet, path, nil, &existing); err != nil {
		return err
	}

	if len(existing.Domains) == 0 {
		body := map[string]any{"domain": regex, "comment": "Parental Control", "groups": []int{groupID}, "enabled": true}
		return c.call(ctx, http.MethodPost, "/api/domains/deny/regex", body, nil)
	}

	d := existing.Domains[0]
	if d.Enabled && slices.Contains(d.Groups, groupID) {
		return nil
	}
	if !slices.Contains(d.Groups, groupID) {
		d.Groups = append(d.Groups, groupID)
	}
	body := map[string]any{"comment": d.Comment, "groups": d.Groups, "enabled": true}
	return c.call(ctx, http.MethodPut, path, body, nil)
}

func (c *Client) addClientToGroup(ctx context.Context, ip string, groupID int) error {
	client, err := c.getClient(ctx, ip)
	if errors.Is(err, errNotFound) {
		return c.call(ctx, http.MethodPost, "/api/clients", &ClientItem{IP: ip, Groups: []int{groupID}}, nil)
	}
	if err != nil {
		return err
	}
	if slices.Contains(client.Groups, groupID) {
		return nil
	}
	client.Groups = append(client.Groups, groupID)
	return c.updateClient(ctx, client)
}

func (c *Client) removeClientFromGroup(ctx context.Context, ip string, groupID int) error {
	client, err := c.getClient(ctx, ip)
	if errors.Is(err, errNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}
	if !slices.Contains(client.Groups, groupID) {
		return nil
	}
	client.Groups = slices.DeleteFunc(client.Groups, func(g int) bool { return g == groupID })
	return c.updateClient(ctx, client)
}

func (c *Client) getClient(ctx context.Context, ip string) (*ClientItem, error) {
	var response struct {
		Clients []ClientItem `json:"clients"`
	}
	if err := c.call(ctx, http.MethodGet, "/api/clients/"+url.PathEscape(ip), nil, &response); err != nil {
		return nil, err
	}
	for _, cl := range response.Clients {
		if cl.IP == ip {
			return &cl, nil
		}
	}
	return nil, fmt.Errorf("client %s: %w", ip, errNotFound)
}

func (c *Client) updateClient(ctx context.Context, client *ClientItem) error {
	body := map[string]any{"comment": client.Comment, "groups": client.Groups}
	return c.call(ctx, http.MethodPut, "/api/clients/"+url.PathEscape(client.IP), body, nil)
}
