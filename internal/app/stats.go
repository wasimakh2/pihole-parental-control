package app

import (
	"fmt"
	"sort"
	"time"

	"github.com/vladikamira/pihole-parental-control/internal/pihole"
)

func applyQueries(stats *DomainStats, results []*pihole.QueryStats) {
	for _, queryStats := range results {
		stats.GlobalCount += len(queryStats.Queries)

		// Sort queries by time to ensure chronological processing
		sort.Slice(queryStats.Queries, func(i, j int) bool {
			return queryStats.Queries[i].Time < queryStats.Queries[j].Time
		})

		for _, query := range queryStats.Queries {
			if !checkIfClientExist(stats, query.Client.IP) {
				stats.Clients = append(stats.Clients, NewClientStats(query.Client.IP))
			}
			if query.Client.Name != nil {
				setClientName(stats, query.Client.IP, *query.Client.Name)
			}

			// update client stats and register and check time interval
			qTime := time.Unix(int64(query.Time), 0)
			updateClientStats(stats, query.Client.IP, qTime)
		}
	}
}

func updateClientStats(stats *DomainStats, ip string, t time.Time) {
	for _, client := range stats.Clients {
		if client.IP == ip {
			// Skip if we've already processed this query or newer ones
			if !t.After(client.LastQueryTime) && !client.LastQueryTime.IsZero() {
				return
			}
			client.LastQueryTime = t
			client.RequestsToday++

			if len(client.WatchIntervals) == 0 {
				client.WatchIntervals = append(client.WatchIntervals, WatchIntervals{
					Start:    t,
					End:      t.Add(5 * time.Minute),
					Requests: 1,
				})
				client.TimeWatchedToday += 5 * time.Minute
				return
			}

			// check if last interval is active
			lastInterval := &client.WatchIntervals[len(client.WatchIntervals)-1]
			if t.After(lastInterval.Start) && t.Before(lastInterval.End) {
				lastInterval.Requests++
			} else {
				// check diff with previous window
				diff := t.Sub(lastInterval.End)
				start := t
				if diff < 5*time.Minute {
					start = lastInterval.End
				}

				client.WatchIntervals = append(client.WatchIntervals, WatchIntervals{
					Start:    start,
					End:      start.Add(5 * time.Minute),
					Requests: 1,
				})
				client.TimeWatchedToday += 5 * time.Minute
			}
		}
	}
}

func NewClientStats(ip string) *Client {
	return &Client{
		RequestsToday:    0,
		IP:               ip,
		TimeWatchedToday: time.Duration(0),
	}
}

func findClient(stats *DomainStats, ip string) *Client {
	for _, client := range stats.Clients {
		if client.IP == ip {
			return client
		}
	}
	return nil
}

func setClientName(stats *DomainStats, ip, name string) {
	if client := findClient(stats, ip); client != nil {
		client.Name = name
	}
}

func checkIfClientExist(stats *DomainStats, ip string) bool {
	return findClient(stats, ip) != nil
}

func printStats(stats *DomainStats) {
	for _, client := range stats.Clients {
		fmt.Printf("Client %s timeWatched: %v Requests: %d\n", client.IP, client.TimeWatchedToday, client.RequestsToday)
		for _, interval := range client.WatchIntervals {
			fmt.Printf("  Interval Start: %s End: %s Requests: %d\n", interval.Start, interval.End, interval.Requests)
		}
	}
}

func today() time.Time {
	y, mo, d := time.Now().Date()
	return time.Date(y, mo, d, 0, 0, 0, 0, time.Local)
}

func resetStats(stats *DomainStats) {
	for _, client := range stats.Clients {
		resetClientStats(client)
	}
}

func resetClientStats(client *Client) {
	client.RequestsToday = 0
	client.TimeWatchedToday = 0
	client.WatchIntervals = nil
	client.NotifiedNearLimit = false
}
