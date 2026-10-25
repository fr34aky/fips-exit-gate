// Command agent is the fips-exit node agent. It reconciles the nftables
// `authorized` set against the backend (long-poll delta sync) and reports
// per-service usage read from the nftables `acct` counters, applying inline
// revocations for prompt quota cutoff. It shells out to nft, so it runs on both
// Ubuntu and OpenWrt with no extra dependencies.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/logging"
)

func main() {
	logging.Setup("agent")
	baseURL := os.Getenv("FIPS_AGENT_BACKEND_URL")
	if baseURL == "" {
		log.Fatal("agent: FIPS_AGENT_BACKEND_URL is required")
	}
	if err := checkBackendURL(baseURL, os.Getenv("FIPS_AGENT_ALLOW_INSECURE") == "1"); err != nil {
		log.Fatalf("agent: %v", err)
	}
	stateDir := getenv("FIPS_AGENT_STATE_DIR", "/var/lib/fips-exit-agent")
	nftPath := getenv("FIPS_AGENT_NFT", "nft")
	table := getenv("FIPS_AGENT_TABLE", "inet fips_exit")
	nodeName := getenv("FIPS_AGENT_NODE_NAME", hostnameOr("fips-exit"))
	enrollToken := os.Getenv("FIPS_AGENT_ENROLL_TOKEN")
	failClosed := os.Getenv("FIPS_AGENT_FAIL_CLOSED_AFTER_GRACE") == "1"
	bufferCap := getenvInt("FIPS_AGENT_USAGE_BUFFER_CAP", 2880) // ~24h at 30s

	st, err := openStore(stateDir)
	if err != nil {
		log.Fatalf("agent: state: %v", err)
	}
	client := newBackendClient(baseURL)
	fw := newNftFirewall(nftPath, table)
	a := newAgent(st, client, fw, nodeName, enrollToken, failClosed, bufferCap)
	// 0 disables the periodic full reconcile; positive values are floored at
	// 30 s so a typo can't turn the sync loop into a full-set firehose.
	if fs := getenvInt("FIPS_AGENT_FULL_SYNC_S", 300); fs <= 0 {
		a.fullSyncEvery = 0
	} else {
		a.fullSyncEvery = time.Duration(clampInt(fs, 30, 1<<20)) * time.Second
	}
	a.heartbeatEvery = time.Duration(getenvInt("FIPS_AGENT_HEARTBEAT_S", 60)) * time.Second
	a.longPollWait = time.Duration(clampInt(getenvInt("FIPS_AGENT_LONGPOLL_S", 50), 5, 55)) * time.Second
	a.massRevokeMin = getenvInt("FIPS_AGENT_MASS_REVOKE_MIN", 50)
	a.allowMassRevoke = os.Getenv("FIPS_AGENT_ALLOW_MASS_REVOKE") == "1"
	if a.allowMassRevoke {
		log.Printf("agent: FIPS_AGENT_ALLOW_MASS_REVOKE=1 — full reconciles may revoke most of the set")
	}
	// WireGuard whole-device service: mirror the backend's peer table onto
	// FIPS_AGENT_WG_IF and announce this node's key + endpoint.
	if wgIf := os.Getenv("FIPS_AGENT_WG_IF"); wgIf != "" {
		a.wg = newWgTool(getenv("FIPS_AGENT_WG", "wg"), wgIf)
		a.wgEndpoint = os.Getenv("FIPS_AGENT_WG_ENDPOINT") // e.g. npub1…exit….fips:51820
		if a.wgEndpoint == "" {
			log.Fatal("agent: FIPS_AGENT_WG_ENDPOINT is required with FIPS_AGENT_WG_IF (what clients should dial)")
		}
		if s := getenvInt("FIPS_AGENT_WG_SYNC_S", 15); s > 0 {
			a.wgSyncEvery = time.Duration(s) * time.Second
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Metrics (Prometheus text format) if an address is configured.
	if addr := os.Getenv("FIPS_AGENT_METRICS_ADDR"); addr != "" {
		a.metrics = newAgentMetrics()
		a.metrics.serve(ctx, addr)
	}

	log.Printf("agent %s starting (backend=%s, table=%q)", agentVersion, baseURL, table)
	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("agent: %v", err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func hostnameOr(def string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return def
}
