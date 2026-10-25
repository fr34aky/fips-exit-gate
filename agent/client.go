package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

// backendClient talks to the fips-exit backend API (docs/api-agent-backend.md).
type backendClient struct {
	baseURL   string
	httpc     *http.Client
	authToken string // empty until enrolled
	nodeID    string
}

// checkBackendURL enforces the transport rule for the agent<->backend
// channel: https anywhere, or plain http only where the path is already
// confidential and authenticated — loopback, a fips address (the mesh
// encrypts end to end), or a .fips name. Anything else needs
// FIPS_AGENT_ALLOW_INSECURE=1, because the bearer token would cross the
// Internet in the clear.
func checkBackendURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("FIPS_AGENT_BACKEND_URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || strings.HasSuffix(host, ".fips") {
			return nil
		}
		if ip, err := netip.ParseAddr(host); err == nil && (ip.IsLoopback() || fipsaddr.Valid(ip)) {
			return nil
		}
		if allowInsecure {
			return nil
		}
		return fmt.Errorf("FIPS_AGENT_BACKEND_URL %q is plain http to a non-fips, non-loopback host: the node token would cross the network unencrypted; use https:// or set FIPS_AGENT_ALLOW_INSECURE=1 knowingly", raw)
	default:
		return fmt.Errorf("FIPS_AGENT_BACKEND_URL %q: scheme must be https:// or http://", raw)
	}
}

func newBackendClient(baseURL string) *backendClient {
	return &backendClient{
		baseURL: baseURL,
		// No overall timeout: authz long-poll holds the request open. Per-call
		// timeouts are applied via context instead.
		httpc: &http.Client{},
	}
}

func (c *backendClient) setAuth(nodeID, token string) {
	c.nodeID, c.authToken = nodeID, token
}

// errUnchanged signals a 204 from the authz long-poll (no changes).
var errUnchanged = fmt.Errorf("authz: unchanged")

func (c *backendClient) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return resp.StatusCode, fmt.Errorf("backend %s %s: %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("backend %s %s: decode: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func (c *backendClient) enroll(ctx context.Context, req enrollRequest) (enrollResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out enrollResponse
	_, err := c.do(ctx, http.MethodPost, "/v1/nodes/enroll", req, &out)
	return out, err
}

// getAuthz issues the long-poll sync. wait is the max seconds the server may
// hold the request; rev is the last applied revision; full asks for the
// complete set immediately (even at backend revision 0) instead of a delta or
// a long-poll. Returns errUnchanged on a 204.
func (c *backendClient) getAuthz(ctx context.Context, rev int64, wait int, full bool) (authzResponse, error) {
	// Client-side deadline slightly beyond the server hold.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(wait+10)*time.Second)
	defer cancel()
	path := "/v1/nodes/" + c.nodeID + "/authz?rev=" + strconv.FormatInt(rev, 10) +
		"&wait=" + strconv.Itoa(wait)
	if full {
		path += "&full=1"
	}
	var out authzResponse
	status, err := c.do(ctx, http.MethodGet, path, nil, &out)
	if err != nil {
		return authzResponse{}, err
	}
	if status == http.StatusNoContent {
		return authzResponse{}, errUnchanged
	}
	return out, nil
}

func (c *backendClient) postUsage(ctx context.Context, report usageReport) (usageAck, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out usageAck
	_, err := c.do(ctx, http.MethodPost, "/v1/nodes/"+c.nodeID+"/usage", report, &out)
	return out, err
}

func (c *backendClient) heartbeat(ctx context.Context, req heartbeatRequest) (heartbeatResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out heartbeatResponse
	_, err := c.do(ctx, http.MethodPost, "/v1/nodes/"+c.nodeID+"/heartbeat", req, &out)
	return out, err
}
