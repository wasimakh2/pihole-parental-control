package app

import (
	"context"
	"fmt"
	"time"

	"github.com/vladikamira/pihole-parental-control/internal/config"
	"github.com/vladikamira/pihole-parental-control/internal/pihole"
	"github.com/vladikamira/pihole-parental-control/internal/speaker"
	"github.com/vladikamira/pihole-parental-control/internal/telegram"
)

func NewApp() *App {
	cfg := config.NewConfig()
	client := pihole.NewClient(cfg)
	tgClient := telegram.NewClient(cfg)
	speakerClient := speaker.NewClient(cfg)

	stats := DomainStats{
		Domains:     cfg.DomainsToCheck,
		GlobalCount: 0,
		DailyLimit:  cfg.DaylyWatchingLimit,
	}
	// Seed limited clients so they show up before their first query.
	for _, ip := range cfg.LimitedClients {
		client := NewClientStats(ip)
		client.Limited = true
		stats.Clients = append(stats.Clients, client)
	}

	return &App{
		cfg:           cfg,
		client:        client,
		tgClient:      tgClient,
		speakerClient: speakerClient,
		stats:         stats,
		limiter:       newFailLimiter(),
	}
}

func (a *App) Run() {
	a.StartServer()
	fmt.Printf("Starting app with config: %v\n", a.cfg)
	a.syncBlocked()

	day := today()
	unblockPending := false
	for {
		// Checked first, so a Pi-hole outage at midnight delays the reset instead of skipping it.
		if d := today(); !d.Equal(day) {
			day, unblockPending = d, true
			a.mu.Lock()
			resetStats(&a.stats)
			a.mu.Unlock()
		}
		if unblockPending {
			unblockPending = !a.unblockAll()
		}

		// Pi-hole is queried without a.mu held so /stats and the UI stay responsive.
		results, err := fetchQueries(a.client, a.cfg.DomainsToCheck)
		if err != nil {
			fmt.Printf("Failed to check domains: %v\n", err)
			time.Sleep(a.cfg.CheckInternal)
			continue
		}

		a.mu.Lock()
		applyQueries(&a.stats, results)
		printStats(&a.stats)
		nearLimit, toBlock := a.collect()
		a.mu.Unlock()

		// Telegram and speaker calls run with no lock held, so they never stall the UI.
		for _, ip := range nearLimit {
			a.notify(fmt.Sprintf("Client %s has less than 5 minutes left", ip), a.cfg.NearLimitMessage)
		}
		a.blockClients(toBlock)
		time.Sleep(a.cfg.CheckInternal)
	}
}

// collect marks near-limit warnings as sent and returns who to warn and who to block. Caller holds a.mu.
func (a *App) collect() (nearLimit, toBlock []string) {
	for _, client := range a.stats.Clients {
		client.Limited = a.cfg.IsLimited(client.IP)
		if !client.Limited || client.Blocked {
			continue
		}
		remaining := a.cfg.DaylyWatchingLimit - client.TimeWatchedToday
		if !client.NotifiedNearLimit && remaining <= 5*time.Minute && remaining > 0 {
			client.NotifiedNearLimit = true
			nearLimit = append(nearLimit, client.IP)
		}
		if client.TimeWatchedToday > a.cfg.DaylyWatchingLimit {
			toBlock = append(toBlock, client.IP)
		}
	}
	return nearLimit, toBlock
}

func (a *App) notify(message, spoken string) {
	fmt.Println(message)
	a.tgClient.SendMessage(message)
	if spoken == "" {
		return
	}
	if err := a.speakerClient.Speak(spoken); err != nil {
		fmt.Printf("Failed to speak message: %v\n", err)
	}
}

func (a *App) blockClients(ips []string) {
	for _, ip := range ips {
		blocked, err := a.blockIfStillOver(ip)
		switch {
		case err != nil:
			a.notify(fmt.Sprintf("Failed to block client %s: %v", ip, err), "")
		case blocked:
			a.notify(fmt.Sprintf("Client %s reached limit %s and is now blocked", ip, a.cfg.DaylyWatchingLimit), a.cfg.LimitReachedMessage)
		}
	}
}

func (a *App) blockIfStillOver(ip string) (bool, error) {
	a.actionMu.Lock()
	defer a.actionMu.Unlock()
	// A parent may have reset this device since collect ran.
	a.mu.RLock()
	c := findClient(&a.stats, ip)
	still := c != nil && !c.Blocked && c.TimeWatchedToday > a.cfg.DaylyWatchingLimit
	a.mu.RUnlock()
	if !still {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), piholeTimeout)
	defer cancel()
	if err := a.client.BlockDomainsForClient(ctx, ip, a.cfg.DomainsToCheck); err != nil {
		return false, err
	}
	a.setBlocked(ip, true)
	return true, nil
}

// unblockAll lifts every known device's block and reports whether all succeeded;
// failures are retried on the next loop. Unblocking an unblocked device is a no-op
// in Pi-hole, so devices memory forgot after a restart are covered too.
func (a *App) unblockAll() bool {
	var failed []string
	a.actionMu.Lock()
	for _, ip := range a.clientIPs() {
		ctx, cancel := context.WithTimeout(context.Background(), piholeTimeout)
		err := a.client.UnblockDomainsForClient(ctx, ip)
		cancel()
		if err != nil {
			fmt.Printf("Failed to unblock client %s: %v\n", ip, err)
			failed = append(failed, ip)
			continue
		}
		a.setBlocked(ip, false)
	}
	a.actionMu.Unlock()
	if len(failed) > 0 {
		a.notify(fmt.Sprintf("Failed to unblock %v; retrying", failed), "")
	}
	return len(failed) == 0
}

// syncBlocked reads which known devices Pi-hole blocks, so state survives a restart.
func (a *App) syncBlocked() {
	for _, ip := range a.clientIPs() {
		ctx, cancel := context.WithTimeout(context.Background(), piholeTimeout)
		blocked, err := a.client.IsBlocked(ctx, ip)
		cancel()
		if err != nil {
			fmt.Printf("Failed to read block state of %s: %v\n", ip, err)
			continue
		}
		a.setBlocked(ip, blocked)
	}
}

func (a *App) clientIPs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ips := make([]string, 0, len(a.stats.Clients))
	for _, c := range a.stats.Clients {
		ips = append(ips, c.IP)
	}
	return ips
}

func (a *App) setBlocked(ip string, blocked bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c := findClient(&a.stats, ip); c != nil {
		c.Blocked = blocked
	}
}

func fetchQueries(client *pihole.Client, domains []string) ([]*pihole.QueryStats, error) {
	results := make([]*pihole.QueryStats, 0, len(domains))
	for _, domain := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), piholeTimeout)
		queryStats, err := client.GetDomainStats(ctx, domain)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("get domain stats failed: %v", err)
		}
		results = append(results, queryStats)
	}
	return results, nil
}
