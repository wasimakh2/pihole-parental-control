package main

import (
	// Alpine image ships no zoneinfo; without this TZ is ignored and the daily reset runs at UTC midnight.
	_ "time/tzdata"

	"github.com/vladikamira/pihole-parental-control/internal/app"
)

func main() {
	app.NewApp().Run()
}
