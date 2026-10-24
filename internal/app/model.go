package app

import (
	"sync"
	"time"

	"github.com/vladikamira/pihole-parental-control/internal/config"
	"github.com/vladikamira/pihole-parental-control/internal/pihole"
	"github.com/vladikamira/pihole-parental-control/internal/speaker"
	"github.com/vladikamira/pihole-parental-control/internal/telegram"
)

type WatchIntervals struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Requests int       `json:"requests"`
}

type App struct {
	cfg           config.Config
	client        *pihole.Client
	tgClient      *telegram.Client
	speakerClient *speaker.Client
	stats         DomainStats
	mu            sync.RWMutex
	// actionMu serialises block/unblock decisions with their Pi-hole calls, so a
	// concurrent reset and block cannot leave memory and Pi-hole disagreeing.
	actionMu sync.Mutex
	limiter  *failLimiter
}

// piholeTimeout bounds one block, unblock or stats call, below the UI's 20 s wait.
const piholeTimeout = 15 * time.Second

type Client struct {
	RequestsToday     int              `json:"requests_today"`
	IP                string           `json:"ip"`
	TimeWatchedToday  time.Duration    `json:"time_watched_today"`
	WatchIntervals    []WatchIntervals `json:"watch_intervals"`
	LastQueryTime     time.Time        `json:"last_query_time"`
	Blocked           bool             `json:"blocked"`
	NotifiedNearLimit bool             `json:"notified_near_limit"`
	Name              string           `json:"name"`
	Limited           bool             `json:"limited"`
}

type DomainStats struct {
	Domains     []string      `json:"domains"`
	GlobalCount int           `json:"global_count"`
	Clients     []*Client     `json:"clients"`
	DailyLimit  time.Duration `json:"daily_limit_ns"`
}
