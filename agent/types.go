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
	// WgPubkey/WgEndpoint announce this node's WireGuard service (empty when
	// the node does not run one); the portal renders client configs from them.
	WgPubkey   string `json:"wg_pubkey,omitempty"`
	WgEndpoint string `json:"wg_endpoint,omitempty"`
}

// wgPeerInfo is one row of the backend's WireGuard peer table.
type wgPeerInfo struct {
	Pubkey string `json:"pubkey"`
	Addr   string `json:"addr"` // issuing fips address (informational)
	IP4    string `json:"ip4"`  // inner /32
	IP6    string `json:"ip6"`  // inner /128
}

// wgPeersResponse is GET /v1/nodes/{id}/wg; a 204 means "unchanged".
type wgPeersResponse struct {
	Etag  string       `json:"etag"`
	Peers []wgPeerInfo `json:"peers"`
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
	Wg             wgConfig      `json:"wg"`
}

// wgConfig is the backend's WireGuard address plan, used to warn when this
// node's deploy/.env disagrees with it.
type wgConfig struct {
	Port  int    `json:"port"`
	Pool4 string `json:"pool4"`
	Pool6 string `json:"pool6"`
}
