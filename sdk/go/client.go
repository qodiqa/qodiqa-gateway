package qodiqa

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Version of this SDK.
const Version = "1.0.0"

//go:embed operations.json
var operationsJSON []byte

// Operation describes one documented operation of the HTTP contract (generated from docs/api/openapi.json; see scripts/sdk/generate-operations.js).
type Operation struct {
	ID            string   `json:"id"`
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Auth          string   `json:"auth"` // ops | sign | none | optional
	PathParams    []string `json:"pathParams"`
	Query         []string `json:"query"`
	RequiredQuery []string `json:"requiredQuery"`
	Headers       []string `json:"headers"`
	Body          string   `json:"body"` // json | form | raw | none
	BodyRequired  bool     `json:"bodyRequired"`
	Response      string   `json:"response"` // json | sse | text | binary | none
	Summary       string   `json:"summary"`
}

var operations map[string]*Operation

func init() {
	var doc struct {
		ContractSha256 string       `json:"contractSha256"`
		Operations     []*Operation `json:"operations"`
	}
	if err := json.Unmarshal(operationsJSON, &doc); err != nil {
		panic("qodiqa: embedded operations.json is invalid: " + err.Error())
	}
	operations = make(map[string]*Operation, len(doc.Operations))
	for _, o := range doc.Operations {
		operations[o.ID] = o
	}
}

// Operations lists every operation this SDK version can call, sorted by id.
func Operations() []Operation {
	out := make([]Operation, 0, len(operations))
	for _, o := range operations {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Config configures a Client.
type Config struct {
	BaseURL     string        // required, e.g. https://gateway.example.com
	APIKey      string        // operator key (ok_...) for admin operations
	SignToken   string        // signing key (sk_...) for POST /sign
	Timeout     time.Duration // for the whole call including retries; default 30 s
	MaxRetries  int           // retries of a request that is safe to resend: 0 = the default (2), a negative value = none
	HTTPClient  *http.Client  // default: a client without its own timeout (Timeout is applied per call)
	OTPProvider func(ctx context.Context) (string, error)
	UserAgent   string
}

// Client calls a QODIQA gateway.
type Client struct {
	cfg  Config
	base *url.URL
	hc   *http.Client
}

// New validates the configuration.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, validationError("BaseURL is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, validationError("BaseURL must be an http(s) URL without credentials")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	switch {
	case cfg.MaxRetries == 0:
		cfg.MaxRetries = 2
	case cfg.MaxRetries < 0:
		cfg.MaxRetries = 0
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "qodiqa-go/" + Version
	}
	return &Client{cfg: cfg, base: u, hc: hc}, nil
}

// CallArgs are the arguments of a call. Path values are URL-escaped; Query/Headers must be declared by the operation.
type CallArgs struct {
	Path    map[string]string
	Query   map[string]string
	Headers map[string]string
	Body    any // marshalled as JSON
}

// Response is the answer of a non-streaming call.
type Response struct {
	Status      int
	Header      http.Header
	ContentType string
	Raw         []byte // the body as received (a PDF stays bytes)
}

// JSON decodes the body (numbers stay exact as json.Number).
func (r *Response) JSON() (any, error) { return ParseJSON(r.Raw) }

// Text returns the body as a string.
func (r *Response) Text() string { return string(r.Raw) }

var placeholder = regexp.MustCompile(`\{([^}]+)\}`)

func (c *Client) prepare(op *Operation, a CallArgs) (string, url.Values, http.Header, []byte, error) {
	for k := range a.Path {
		if !contains(op.PathParams, k) {
			return "", nil, nil, nil, validationError("%s: unknown path parameter %q", op.ID, k)
		}
	}
	var perr error
	path := placeholder.ReplaceAllStringFunc(op.Path, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := a.Path[name]
		if !ok || v == "" {
			perr = validationError("%s: path parameter %q is required", op.ID, name)
			return m
		}
		return url.PathEscape(v)
	})
	if perr != nil {
		return "", nil, nil, nil, perr
	}
	q := url.Values{}
	for k, v := range a.Query {
		if !contains(op.Query, k) {
			return "", nil, nil, nil, validationError("%s: unknown query parameter %q", op.ID, k)
		}
		q.Set(k, v)
	}
	for _, k := range op.RequiredQuery {
		if _, ok := a.Query[k]; !ok {
			return "", nil, nil, nil, validationError("%s: query parameter %q is required", op.ID, k)
		}
	}
	var body []byte
	switch {
	case op.Body == "none" && a.Body != nil:
		return "", nil, nil, nil, validationError("%s: this operation takes no request body", op.ID)
	case op.BodyRequired && a.Body == nil:
		return "", nil, nil, nil, validationError("%s: a request body is required", op.ID)
	case op.Body == "form" || op.Body == "raw":
		return "", nil, nil, nil, validationError("%s: %s request bodies are not supported by the generic client", op.ID, op.Body)
	case a.Body != nil:
		b, err := json.Marshal(a.Body)
		if err != nil {
			return "", nil, nil, nil, validationError("%s: the body cannot be encoded as JSON: %v", op.ID, err)
		}
		body = b
	}
	h := http.Header{}
	for k, v := range a.Headers {
		ok := false
		for _, d := range op.Headers {
			ok = ok || strings.EqualFold(d, k)
		}
		if !ok {
			return "", nil, nil, nil, validationError("%s: unknown header %q", op.ID, k)
		}
		h.Set(k, v)
	}
	switch op.Auth {
	case "ops":
		if c.cfg.APIKey == "" {
			return "", nil, nil, nil, &Error{Kind: KindAuthentication, Reason: "UNAUTHENTICATED", Message: "an operator API key (Config.APIKey) is required for " + op.ID}
		}
		h.Set("Authorization", "Bearer "+c.cfg.APIKey)
	case "sign":
		if c.cfg.SignToken == "" {
			return "", nil, nil, nil, &Error{Kind: KindAuthentication, Reason: "UNAUTHENTICATED", Message: "a signing key (Config.SignToken) is required for " + op.ID}
		}
		h.Set("Authorization", "Bearer "+c.cfg.SignToken)
	case "optional":
		if c.cfg.APIKey != "" {
			h.Set("Authorization", "Bearer "+c.cfg.APIKey)
		}
	}
	return path, q, h, body, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (c *Client) operation(id string) (*Operation, error) {
	op, ok := operations[id]
	if !ok {
		return nil, validationError("unknown operation %q", id)
	}
	return op, nil
}

func (c *Client) newRequest(ctx context.Context, op *Operation, path string, q url.Values, h http.Header, body []byte) (*http.Request, error) {
	u := *c.base
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return nil, validationError("%s: invalid path %q", op.ID, path)
	}
	u.Path = strings.TrimRight(c.base.Path, "/") + unescaped
	u.RawPath = strings.TrimRight(c.base.EscapedPath(), "/") + path // keep %2F inside a segment as %2F
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), rd)
	if err != nil {
		return nil, validationError("%s: cannot build the request: %v", op.ID, err)
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json, text/plain;q=0.5, */*;q=0.1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// Call performs a non-streaming operation by its operationId (see Operations()).
func (c *Client) Call(ctx context.Context, id string, args CallArgs) (*Response, error) {
	op, err := c.operation(id)
	if err != nil {
		return nil, err
	}
	if op.Response == "sse" {
		return nil, validationError("%s streams events: use Stream", op.ID)
	}
	path, q, h, body, err := c.prepare(op, args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.withOTP(ctx, op, path, q, h, body)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// withOTP sends the request and, when the gateway asks for an operator MFA code (MFA_REQUIRED) and an OTPProvider is configured, resends it ONCE with the code
// (the step-up refuses before the handler runs, so the resend is safe). A request that already carries a code is never retried.
func (c *Client) withOTP(ctx context.Context, op *Operation, path string, q url.Values, h http.Header, body []byte) (*Response, error) {
	resp, err := c.send(ctx, op, path, q, h, body)
	if e, ok := AsError(err); ok && e.Kind == KindMFARequired && e.Reason == "MFA_REQUIRED" && c.cfg.OTPProvider != nil && h.Get("X-QODIQA-OTP") == "" {
		otp, perr := c.cfg.OTPProvider(ctx)
		if perr != nil {
			return nil, &Error{Kind: KindOther, Reason: "OTP_PROVIDER_FAILED", Message: "the OTP provider failed: " + perr.Error(), Err: perr}
		}
		h2 := h.Clone()
		h2.Set("X-QODIQA-OTP", otp)
		return c.send(ctx, op, path, q, h2, body)
	}
	return resp, err
}

var chatPath = regexp.MustCompile(`(^|/)ai/chat(/stream)?/?$`)

// shouldRetry follows the gateway's contract: SERVER_OVERLOADED is always safe to resend (refused before decoding); MFA_LOCKED never; idempotent verbs retry 429/5xx;
// POST/PATCH only on 429, and not on /ai/chat (a 429 there may come after the artifact nonce was consumed, so a resend would hide the real answer as a replay).
func shouldRetry(err *Error, method, path string, hasOTP bool) bool {
	if hasOTP || err.Reason == "MFA_LOCKED" {
		return false
	}
	if err.Reason == "SERVER_OVERLOADED" {
		return true
	}
	switch method {
	case "GET", "PUT", "DELETE", "HEAD":
		return err.Status == 429 || err.Status == 500 || err.Status == 502 || err.Status == 503 || err.Status == 504
	}
	return err.Status == 429 && !chatPath.MatchString(path)
}

func (c *Client) send(ctx context.Context, op *Operation, path string, q url.Values, h http.Header, body []byte) (*Response, error) {
	var last error
	for attempt := 0; ; attempt++ {
		req, err := c.newRequest(ctx, op, path, q, h, body)
		if err != nil {
			return nil, err
		}
		resp, err := c.do(req, op)
		if err == nil {
			return resp, nil
		}
		last = err
		e, ok := AsError(err)
		if !ok || attempt >= c.cfg.MaxRetries || !shouldRetry(e, op.Method, path, h.Get("X-QODIQA-OTP") != "") {
			return nil, err
		}
		wait := backoff(attempt)
		if e.RetryAfter > 0 {
			wait = time.Duration(e.RetryAfter) * time.Second
		}
		if dl, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(dl) {
			return nil, last // the wait would outlive the call: surface the real error
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, c.ctxError(ctx, op)
		}
	}
}

func backoff(attempt int) time.Duration {
	d := 500 * time.Millisecond << attempt
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d/2 + time.Duration(rand.Int63n(int64(d/2)+1))
}

func (c *Client) ctxError(ctx context.Context, op *Operation) *Error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &Error{Kind: KindTimeout, Reason: "TIMEOUT", Message: fmt.Sprintf("%s timed out after %s", op.ID, c.cfg.Timeout), Err: ctx.Err()}
	}
	return &Error{Kind: KindNetwork, Reason: "CANCELLED", Message: op.ID + " was cancelled", Err: ctx.Err()}
}

func (c *Client) do(req *http.Request, op *Operation) (*Response, error) {
	res, err := c.hc.Do(req)
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, c.ctxError(req.Context(), op)
		}
		return nil, &Error{Kind: KindNetwork, Reason: "NETWORK", Message: fmt.Sprintf("network error on %s %s: %v", op.Method, op.Path, err), Err: err}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, c.ctxError(req.Context(), op)
		}
		return nil, &Error{Kind: KindNetwork, Reason: "NETWORK", Message: "reading the response failed: " + err.Error(), Err: err}
	}
	r := &Response{Status: res.StatusCode, Header: res.Header, ContentType: res.Header.Get("Content-Type"), Raw: raw}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return r, nil
	}
	return nil, errorFromResponse(r)
}

var codeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

// errorFromResponse reads every error shape of the gateway: the decision envelope, the management envelope {status:'error', error:{code, message, details}}, and the flat limiter body.
func errorFromResponse(r *Response) *Error {
	reason, message := "UNKNOWN", fmt.Sprintf("HTTP %d %s", r.Status, http.StatusText(r.Status))
	requestID := ""
	details := map[string]any{}
	if strings.Contains(r.ContentType, "application/json") {
		if v, err := ParseJSON(r.Raw); err == nil {
			if b, ok := v.(map[string]any); ok {
				if s, ok := b["reason"].(string); ok {
					reason = s
				}
				if s, ok := b["requestId"].(string); ok {
					requestID = s
				}
				if d, ok := b["details"].(map[string]any); ok {
					details = d
					if m, ok := d["message"].(string); ok {
						message = m
					}
				}
				if s, ok := b["message"].(string); ok {
					message = s
				}
				if eo, ok := b["error"].(map[string]any); ok {
					if s, ok := eo["code"].(string); ok {
						reason = s
					}
					if s, ok := eo["message"].(string); ok {
						message = s
					}
					if d, ok := eo["details"].(map[string]any); ok {
						for k, x := range d {
							details[k] = x
						}
					}
				}
				if s, ok := b["error"].(string); ok && codeRE.MatchString(s) {
					if rs, ok := b["reason"].(string); ok {
						details["blockedBy"] = rs
					}
					reason = s
					for _, k := range []string{"surface", "dimension", "retryAfterSeconds"} {
						if x, ok := b[k]; ok && x != nil {
							details[k] = x
						}
					}
				}
			}
		}
	}
	retryAfter := parseRetryAfter(r.Header.Get("Retry-After"))
	if retryAfter > 0 {
		details["retryAfter"] = retryAfter
	}
	if requestID == "" {
		requestID = r.Header.Get("X-Request-ID")
	}
	return &Error{Kind: classify(r.Status, reason), Status: r.Status, Reason: reason, Message: message, RequestID: requestID, Details: details, RetryAfter: retryAfter}
}

// parseRetryAfter reads delta-seconds or an HTTP-date; anything else is 0.
func parseRetryAfter(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return n
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := int(time.Until(t).Seconds() + 0.999); d > 0 {
			return d
		}
	}
	return 0
}

// Stream performs an SSE operation. The caller must Close the stream. There is no automatic retry (a partly consumed stream is not restartable).
func (c *Client) Stream(ctx context.Context, id string, args CallArgs) (*EventStream, error) {
	op, err := c.operation(id)
	if err != nil {
		return nil, err
	}
	if op.Response != "sse" {
		return nil, validationError("%s does not stream events: use Call", op.ID)
	}
	path, q, h, body, err := c.prepare(op, args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	req, err := c.newRequest(ctx, op, path, q, h, body)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	res, err := c.hc.Do(req)
	if err != nil {
		cancel()
		return nil, &Error{Kind: KindNetwork, Reason: "NETWORK", Message: fmt.Sprintf("network error on %s %s: %v", op.Method, op.Path, err), Err: err}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		cancel()
		return nil, errorFromResponse(&Response{Status: res.StatusCode, Header: res.Header, ContentType: res.Header.Get("Content-Type"), Raw: raw})
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	return &EventStream{body: res.Body, sc: sc, cancel: cancel}, nil
}

// EventStream yields the JSON events of an SSE response until the terminal [DONE] frame.
type EventStream struct {
	body   io.ReadCloser
	sc     *bufio.Scanner
	cancel context.CancelFunc
	done   bool
}

// Next returns the next event, or (nil, io.EOF) after the [DONE] frame. A stream that ends before [DONE] is an error (truncated).
func (s *EventStream) Next() (any, error) {
	if s.done {
		return nil, io.EOF
	}
	var data []string
	for s.sc.Scan() {
		line := s.sc.Text()
		if line == "" {
			if len(data) == 0 {
				continue
			}
			payload := strings.Join(data, "\n")
			data = data[:0]
			if payload == "[DONE]" {
				s.done = true
				return nil, io.EOF
			}
			v, err := ParseJSON([]byte(payload))
			if err != nil {
				return nil, &Error{Kind: KindOther, Reason: "INVALID_EVENT", Message: "an event is not valid JSON: " + err.Error(), Err: err}
			}
			return v, nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(rest, " "))
		}
	}
	if err := s.sc.Err(); err != nil {
		return nil, &Error{Kind: KindNetwork, Reason: "NETWORK", Message: "reading the stream failed: " + err.Error(), Err: err}
	}
	return nil, &Error{Kind: KindNetwork, Reason: "TRUNCATED_STREAM", Message: "the stream ended before the terminal [DONE] frame"}
}

// Close releases the connection.
func (s *EventStream) Close() error { s.cancel(); return s.body.Close() }
