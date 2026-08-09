package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func render(r *Registry) string {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func TestCounterAndGauge(t *testing.T) {
	r := New()
	c := r.Counter("fips_c_total", "a counter")
	c.Inc()
	c.Add(4)
	g := r.Gauge("fips_g", "a gauge")
	g.Set(7)
	g.Dec()

	out := render(r)
	for _, want := range []string{
		"# HELP fips_c_total a counter",
		"# TYPE fips_c_total counter",
		"fips_c_total 5",
		"# TYPE fips_g gauge",
		"fips_g 6",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestVecLabelsSortedAndEscaped(t *testing.T) {
	r := New()
	wh := r.CounterVec("fips_webhook_total", "webhooks", "type", "result")
	wh.With("InvoiceSettled", "ok").Inc()
	wh.With("InvoiceSettled", "ok").Inc()
	wh.With("InvoiceInvalid", "ok").Inc()

	out := render(r)
	if !strings.Contains(out, `fips_webhook_total{result="ok",type="InvoiceSettled"} 2`) {
		t.Fatalf("labeled counter wrong (labels must be sorted):\n%s", out)
	}
	if !strings.Contains(out, `fips_webhook_total{result="ok",type="InvoiceInvalid"} 1`) {
		t.Fatalf("second series missing:\n%s", out)
	}
	// HELP/TYPE printed once per family.
	if strings.Count(out, "# TYPE fips_webhook_total") != 1 {
		t.Fatalf("TYPE printed more than once:\n%s", out)
	}
}

func TestCollector(t *testing.T) {
	r := New()
	r.Collect(func() []Sample {
		return []Sample{
			{Name: "fips_accounts", Help: "accounts", Type: "gauge", Labels: []string{"status", "active"}, Value: 3},
			{Name: "fips_accounts", Labels: []string{"status", "suspended"}, Value: 1},
		}
	})
	out := render(r)
	if !strings.Contains(out, "# TYPE fips_accounts gauge") {
		t.Fatalf("collector TYPE missing:\n%s", out)
	}
	if strings.Count(out, "# TYPE fips_accounts") != 1 {
		t.Fatalf("collector TYPE not deduped:\n%s", out)
	}
	if !strings.Contains(out, `fips_accounts{status="active"} 3`) || !strings.Contains(out, `fips_accounts{status="suspended"} 1`) {
		t.Fatalf("collector samples wrong:\n%s", out)
	}
}

func TestEscaping(t *testing.T) {
	r := New()
	r.CounterVec("fips_x_total", "h", "path").With(`a"b\c`).Inc()
	out := render(r)
	if !strings.Contains(out, `path="a\"b\\c"`) {
		t.Fatalf("label not escaped:\n%s", out)
	}
}

func TestFloatFormat(t *testing.T) {
	if got := formatFloat(5); got != "5" {
		t.Errorf("int format = %q", got)
	}
	if got := formatFloat(1.5); got != "1.5" {
		t.Errorf("float format = %q", got)
	}
}
