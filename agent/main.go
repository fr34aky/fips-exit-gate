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
)

func main() {
	baseURL := os.Getenv("FIPS_AGENT_BACKEND_URL")
	if baseURL == "" {
		log.Fatal("agent: FIPS_AGENT_BACKEND_URL is required")
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

func hostnameOr(def string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return def
}
