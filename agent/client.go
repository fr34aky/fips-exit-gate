package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// backendClient talks to the fips-exit backend API (docs/api-agent-backend.md).
type backendClient struct {
	baseURL   string
	httpc     *http.Client
	authToken string // empty until enrolled
	nodeID    string
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
// hold the request; rev is the last applied revision. Returns errUnchanged on
// a 204.
func (c *backendClient) getAuthz(ctx context.Context, rev int64, wait int) (authzResponse, error) {
	// Client-side deadline slightly beyond the server hold.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(wait+10)*time.Second)
	defer cancel()
	path := "/v1/nodes/" + c.nodeID + "/authz?rev=" + strconv.FormatInt(rev, 10) +
		"&wait=" + strconv.Itoa(wait)
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
