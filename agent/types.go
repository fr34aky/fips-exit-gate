package main

import "net/netip"

// Wire types for the agent↔backend API (docs/api-agent-backend.md, v1).

type enrollRequest struct {
	EnrollToken string `json:"enroll_token"`
	NodePubkey  string `json:"node_pubkey"` // base64 Ed25519 public key
	Name        string `json:"name"`
}

type enrollResponse struct {
	NodeID    string `json:"node_id"`
	AuthToken string `json:"auth_token"`
}

// authzMember is one authorized fips address and the account it belongs to.
type authzMember struct {
	Addr    netip.Addr `json:"addr"`
	Account string     `json:"account"`
}

// authzResponse is the body of GET /authz. When Full is true, Addresses is the
// complete set; otherwise Add/Del are a delta from the requested rev. A 204 (no
// body) means "unchanged".
type authzResponse struct {
	Rev       int64         `json:"rev"`
	Full      bool          `json:"full"`
	Addresses []authzMember `json:"addresses,omitempty"`
	Add       []authzMember `json:"add,omitempty"`
	Del       []netip.Addr  `json:"del,omitempty"`
}

// usageSample is one client's metered total on one service in the window.
type usageSample struct {
	Service string     `json:"service"`
	Addr    netip.Addr `json:"addr"`
	Bytes   uint64     `json:"bytes"`
}

type usageReport struct {
	ReportID     string        `json:"report_id"`
	CounterEpoch string        `json:"counter_epoch"`
	WindowEnd    string        `json:"window_end"`
	Samples      []usageSample `json:"samples"`
}

type usageAck struct {
	Ack    string       `json:"ack"`
	Revoke []netip.Addr `json:"revoke,omitempty"`
}

type heartbeatRequest struct {
	Version  string `json:"version"`
	AuthzRev int64  `json:"authz_rev"`
	SetSize  int    `json:"set_size"`
}

type serviceInfo struct {
	Key  string `json:"key"`
	Port uint16 `json:"port"`
}

type heartbeatResponse struct {
	Config agentConfig `json:"config"`
	// Resync is set when the backend detects the exit's reported set size
	// disagrees with authz_current at the same revision — i.e. the kernel set
	// has drifted out-of-band. The agent responds by forcing a full reconcile.
	Resync bool `json:"resync,omitempty"`
}

type agentConfig struct {
	UsageIntervalS int           `json:"usage_interval_s"`
	GraceMinutes   int           `json:"grace_minutes"`
	Services       []serviceInfo `json:"services"`
}
