// Package metrics is a tiny, dependency-free Prometheus metrics registry that
// renders the text exposition format. It exists so every fips-exit component —
// including the agent and captive daemon, which are deliberately stdlib-only for
// OpenWrt portability — can expose /metrics without pulling in a metrics library.
//
// It supports counters and gauges (with optional labels) plus scrape-time
// collector callbacks for values sourced on demand (e.g. a database query). It
// is concurrency-safe.
package metrics

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds a set of metric families and renders them.
type Registry struct {
	mu         sync.Mutex
	families   []*family // ordered by registration
	byName     map[string]*family
	collectors []func() []Sample
}

// New returns an empty registry.
func New() *Registry { return &Registry{byName: map[string]*family{}} }

type metricType string

const (
	typeCounter metricType = "counter"
	typeGauge   metricType = "gauge"
)

type family struct {
	name    string
	help    string
	typ     metricType
	mu      sync.Mutex
	series  map[string]*value // keyed by encoded labels
	order   []string          // stable series order
	labelNs []string
}

type value struct {
	bits   uint64 // atomic float64 bits
	labels string // pre-rendered `{k="v",...}` (or "")
}

func (v *value) add(delta float64) {
	for {
		old := atomic.LoadUint64(&v.bits)
		nw := math.Float64bits(math.Float64frombits(old) + delta)
		if atomic.CompareAndSwapUint64(&v.bits, old, nw) {
			return
		}
	}
}
func (v *value) set(f float64) { atomic.StoreUint64(&v.bits, math.Float64bits(f)) }
func (v *value) get() float64  { return math.Float64frombits(atomic.LoadUint64(&v.bits)) }

// Sample is a single value produced by a scrape-time collector.
type Sample struct {
	Name   string
	Help   string
	Type   string   // "counter" or "gauge"; defaults to gauge
	Labels []string // even-length k,v,k,v
	Value  float64
}

func (r *Registry) family(name, help string, typ metricType, labelNames []string) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.byName[name]
	if !ok {
		f = &family{name: name, help: help, typ: typ, series: map[string]*value{}, labelNs: labelNames}
		r.byName[name] = f
		r.families = append(r.families, f)
	}
	return f
}

// Counter is a monotonically increasing value.
type Counter struct{ v *value }

// Inc adds 1. Add adds delta (delta should be >= 0).
func (c *Counter) Inc()          { c.v.add(1) }
func (c *Counter) Add(d float64) { c.v.add(d) }

// Gauge is a value that can go up or down.
type Gauge struct{ v *value }

func (g *Gauge) Set(f float64) { g.v.set(f) }
func (g *Gauge) Inc()          { g.v.add(1) }
func (g *Gauge) Dec()          { g.v.add(-1) }
func (g *Gauge) Add(d float64) { g.v.add(d) }

// Counter returns (creating if needed) an unlabeled counter.
func (r *Registry) Counter(name, help string) *Counter {
	return &Counter{v: r.family(name, help, typeCounter, nil).get("")}
}

// Gauge returns (creating if needed) an unlabeled gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	return &Gauge{v: r.family(name, help, typeGauge, nil).get("")}
}

// CounterVec / GaugeVec are label-parameterised.
type CounterVec struct{ f *family }
type GaugeVec struct{ f *family }

func (r *Registry) CounterVec(name, help string, labelNames ...string) *CounterVec {
	return &CounterVec{f: r.family(name, help, typeCounter, labelNames)}
}
func (r *Registry) GaugeVec(name, help string, labelNames ...string) *GaugeVec {
	return &GaugeVec{f: r.family(name, help, typeGauge, labelNames)}
}

// With returns the counter/gauge for the given label values (in the order the
// vec was created). Values are created on first use.
func (cv *CounterVec) With(labelValues ...string) *Counter {
	return &Counter{v: cv.f.get(zip(cv.f.labelNs, labelValues))}
}
func (gv *GaugeVec) With(labelValues ...string) *Gauge {
	return &Gauge{v: gv.f.get(zip(gv.f.labelNs, labelValues))}
}

// Collect registers a callback invoked at scrape time. Use it for values read on
// demand (e.g. counts from a database). Returned samples are rendered after the
// static families.
func (r *Registry) Collect(fn func() []Sample) {
	r.mu.Lock()
	r.collectors = append(r.collectors, fn)
	r.mu.Unlock()
}

// get returns the value for an encoded label string, creating it if new.
func (f *family) get(labels string) *value {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.series[labels]
	if !ok {
		v = &value{labels: labels}
		f.series[labels] = v
		f.order = append(f.order, labels)
	}
	return v
}

// ServeHTTP renders all metrics in the Prometheus text exposition format.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	r.mu.Lock()
	fams := append([]*family(nil), r.families...)
	cols := append([]func() []Sample(nil), r.collectors...)
	r.mu.Unlock()

	for _, f := range fams {
		writeHeader(&b, f.name, f.help, string(f.typ))
		f.mu.Lock()
		for _, key := range f.order {
			v := f.series[key]
			b.WriteString(f.name)
			b.WriteString(v.labels)
			b.WriteByte(' ')
			b.WriteString(formatFloat(v.get()))
			b.WriteByte('\n')
		}
		f.mu.Unlock()
	}

	// Scrape-time collectors: group samples by name so HELP/TYPE print once.
	seen := map[string]bool{}
	for _, fn := range cols {
		samples := fn()
		// Stable order for deterministic output.
		sort.SliceStable(samples, func(i, j int) bool {
			if samples[i].Name != samples[j].Name {
				return samples[i].Name < samples[j].Name
			}
			return strings.Join(samples[i].Labels, ",") < strings.Join(samples[j].Labels, ",")
		})
		for _, s := range samples {
			if !seen[s.Name] {
				typ := s.Type
				if typ == "" {
					typ = "gauge"
				}
				writeHeader(&b, s.Name, s.Help, typ)
				seen[s.Name] = true
			}
			b.WriteString(s.Name)
			b.WriteString(encodeLabels(pairs(s.Labels)))
			b.WriteByte(' ')
			b.WriteString(formatFloat(s.Value))
			b.WriteByte('\n')
		}
	}
	_, _ = w.Write([]byte(b.String()))
}

func writeHeader(b *strings.Builder, name, help, typ string) {
	if help != "" {
		b.WriteString("# HELP ")
		b.WriteString(name)
		b.WriteByte(' ')
		b.WriteString(escapeHelp(help))
		b.WriteByte('\n')
	}
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(typ)
	b.WriteByte('\n')
}

// zip renders label names+values into `{k="v",...}` sorted by key. Extra or
// missing values are tolerated (best-effort).
func zip(names, values []string) string {
	n := len(names)
	if len(values) < n {
		n = len(values)
	}
	kv := make([][2]string, 0, n)
	for i := 0; i < n; i++ {
		kv = append(kv, [2]string{names[i], values[i]})
	}
	return encodeLabels(kv)
}

func pairs(kv []string) [][2]string {
	out := make([][2]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, [2]string{kv[i], kv[i+1]})
	}
	return out
}

func encodeLabels(kv [][2]string) string {
	if len(kv) == 0 {
		return ""
	}
	sort.Slice(kv, func(i, j int) bool { return kv[i][0] < kv[j][0] })
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range kv {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p[0])
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(p[1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabelValue(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return r.Replace(s)
}
func escapeHelp(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	return r.Replace(s)
}

func formatFloat(f float64) string {
	if f == math.Trunc(f) && !math.IsInf(f, 0) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
