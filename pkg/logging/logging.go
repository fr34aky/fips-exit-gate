// Package logging configures process-wide logging for the fips-exit binaries.
// Every component logs through the standard library's log package; routing
// that through slog gives operators structured (JSON) output with a service
// label and a level, without touching the call sites.
package logging

import (
	"log"
	"log/slog"
	"os"
	"strings"
)

// Setup installs the default slog handler according to LOG_FORMAT ("text",
// the default, or "json") and LOG_LEVEL ("debug" or "info", default "info"),
// tags every record with service=<name>, and redirects the standard log
// package to it (log.Printf -> level INFO, log.Fatal -> exits as before).
//
// Levels above info are deliberately not offered: today every record arrives
// through the std-log bridge at INFO, so "warn" or "error" would silence the
// binaries entirely, including the message of a log.Fatal.
func Setup(service string) {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "", "info":
	case "debug":
		level = slog.LevelDebug
	default:
		defer func() { log.Printf("logging: LOG_LEVEL=%q not supported (use debug|info); using info", os.Getenv("LOG_LEVEL")) }()
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	// SetDefault also points the std log package at this handler (level INFO)
	// and clears its timestamp prefix.
	slog.SetDefault(slog.New(h).With("service", service))
}
