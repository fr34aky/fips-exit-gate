package logging

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestSetupRoutesStdLogThroughSlog(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("LOG_LEVEL", "info")
	// Capture stderr.
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()

	Setup("unit-test")
	log.Printf("hello %d", 42)
	slog.Debug("hidden at info level")
	w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, `"msg":"hello 42"`) || !strings.Contains(out, `"service":"unit-test"`) || !strings.Contains(out, `"level":"INFO"`) {
		t.Fatalf("std log not routed as structured JSON: %q", out)
	}
	if strings.Contains(out, "hidden") {
		t.Fatal("debug record emitted at info level")
	}
}
