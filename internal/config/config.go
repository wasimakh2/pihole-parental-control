package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	PiholeAddress       string
	CheckInternal       time.Duration
	DaylyWatchingLimit  time.Duration
	DomainsToCheck      []string
	LimitedClients      []string
	Password            string
	TelegramToken       string
	TelegramChatID      string
	SpeakerURL          string
	SpeakerLanguage     string
	NearLimitMessage    string
	LimitReachedMessage string
	ApiPort             string
	UIPassword          string
}

func NewConfig() Config {
	return Config{
		PiholeAddress:      os.Getenv("PIHOLE_ADDRESS"),
		CheckInternal:      parseDurationEnv("CHECK_INTERNAL", 1*time.Minute),
		DaylyWatchingLimit: parseDurationEnv("DAILY_WATCHING_LIMIT", parseDurationEnv("DAYLY_WATCHING_LIMIT", 1*time.Hour)),
		DomainsToCheck: parseListEnv("TRACKED_DOMAINS", []string{
			"*youtube*",
			"*googlevideo*",
			"*.ggpht.com",
			"*.youtu.be",
			"*.yt.be",
			"*.ytimg.com",
			"*googleusercontent.com",
		}),
		LimitedClients:      parseListEnv("LIMITED_CLIENTS", nil),
		Password:            os.Getenv("PIHOLE_PASSWORD"),
		TelegramToken:       os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramChatID:      os.Getenv("TELEGRAM_CHAT_ID"),
		SpeakerURL:          os.Getenv("SPEAKER_URL"), // e.g. http://192.168.1.50:8080
		SpeakerLanguage:     getEnv("SPEAKER_LANGUAGE", "en"),
		NearLimitMessage:    getEnv("SPEAKER_NEAR_LIMIT_MESSAGE", "Less than five minutes remaining. Wrap it up."),
		LimitReachedMessage: getEnv("SPEAKER_LIMIT_REACHED_MESSAGE", "Time's up. Viewing is now blocked."),
		ApiPort:             getEnv("API_PORT", "8081"),
		UIPassword:          os.Getenv("UI_PASSWORD"),
	}
}

// String keeps secrets out of the startup log line.
func (c Config) String() string {
	redact := func(s string) string {
		if s == "" {
			return ""
		}
		return "[redacted]"
	}
	c.Password, c.TelegramToken, c.TelegramChatID, c.UIPassword = redact(c.Password), redact(c.TelegramToken), redact(c.TelegramChatID), redact(c.UIPassword)
	type plain Config
	return fmt.Sprintf("%+v", plain(c))
}

// IsLimited reports whether the daily limit is enforced for ip.
// With LIMITED_CLIENTS unset every client is limited, matching the original behaviour.
func (c Config) IsLimited(ip string) bool {
	if len(c.LimitedClients) == 0 {
		return true
	}
	for _, limited := range c.LimitedClients {
		if limited == ip {
			return true
		}
	}
	return false
}

func parseListEnv(key string, fallback []string) []string {
	var items []string
	for _, item := range strings.Split(os.Getenv(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return fallback
	}
	return items
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseDurationEnv(key string, defaultDuration time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultDuration
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return defaultDuration
	}
	return duration
}
