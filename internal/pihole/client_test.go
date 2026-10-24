package pihole

import "testing"

func TestGlobToRegex(t *testing.T) {
	for glob, want := range map[string]string{
		"*youtube*":   `^.*youtube.*$`,
		"*.ytimg.com": `^.*\.ytimg\.com$`,
		"youtu.be":    `^youtu\.be$`,
	} {
		if got := GlobToRegex(glob); got != want {
			t.Errorf("GlobToRegex(%q) = %q, want %q", glob, got, want)
		}
	}
}
