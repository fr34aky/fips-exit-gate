package logging

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// captureSetup runs Setup with stderr redirected to a pipe and returns what
// was written by fn; the process-global defaults are restored afterwards.
func captureSetup(t *testing.T, service string, fn func()) string {
	t.Helper()
	prevDefault, prevFlags, prevOut := slog.Default(), log.Flags(), log.Writer()
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		log.SetFlags(prevFlags)
		log.SetOutput(prevOut)
	})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	Setup(service)
	fn()
	os.Stderr = old
	w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestSetupRoutesStdLogThroughSlog(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("LOG_LEVEL", "info")
	out := captureSetup(t, "unit-test", func() {
		log.Printf("hello %d", 42)
		slog.Debug("hidden at info level")
	})
	if !strings.Contains(out, `"msg":"hello 42"`) || !strings.Contains(out, `"service":"unit-test"`) || !strings.Contains(out, `"level":"INFO"`) {
		t.Fatalf("std log not routed as structured JSON: %q", out)
	}
	if strings.Contains(out, "hidden") {
		t.Fatal("debug record emitted at info level")
	}
}

// warn/error would silence every std-log line; they fall back to info loudly.
func TestUnsupportedLevelFallsBackToInfo(t *testing.T) {
	t.Setenv("LOG_FORMAT", "text")
	t.Setenv("LOG_LEVEL", "warn")
	out := captureSetup(t, "unit-test", func() { log.Printf("still visible") })
	if !strings.Contains(out, "still visible") || !strings.Contains(out, "not supported") {
		t.Fatalf("unsupported level handling: %q", out)
	}
}
