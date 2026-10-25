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
// the default, or "json") and LOG_LEVEL ("debug", "info", "warn", "error"),
// tags every record with service=<name>, and redirects the standard log
// package to it (log.Printf -> level INFO, log.Fatal -> exits as before).
func Setup(service string) {
	var level slog.Level
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	logger := slog.New(h).With("service", service)
	slog.SetDefault(logger)
	// slog.SetDefault already points the log package at the handler; make
	// sure plain log output carries no duplicate timestamp prefix.
	log.SetFlags(0)
}
