package qodiqa

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type seenReq struct {
	Method, URL, Auth, Body, OTP string
}

func newServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *[]seenReq) {
	t.Helper()
	var seen []seenReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, seenReq{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), string(b), r.Header.Get("X-QODIQA-OTP")})
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func jsonOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func TestOperationsCoverTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi.json")
	if err != nil {
		t.Skip("repository checkout required (docs/api/openapi.json)")
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var contract []string
	for p, item := range spec.Paths {
		for m, op := range item {
			switch m {
			case "get", "post", "put", "patch", "delete":
				var o struct {
					OperationID string `json:"operationId"`
				}
				_ = json.Unmarshal(op, &o)
				contract = append(contract, o.OperationID+" "+strings.ToUpper(m)+" "+p)
			}
		}
	}
	var sdk []string
	for _, o := range Operations() {
		sdk = append(sdk, o.ID+" "+o.Method+" "+o.Path)
	}
	sort.Strings(contract)
	sort.Strings(sdk)
	if len(contract) < 300 || strings.Join(contract, "\n") != strings.Join(sdk, "\n") {
		t.Fatalf("the embedded operation table differs from the contract (%d vs %d operations)", len(sdk), len(contract))
	}
}

func TestEveryNonStreamingOperationIsCalledCorrectly(t *testing.T) {
	srv, seen := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/pdf"):
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte{0x25, 0x50, 0x44, 0x46, 0xff, 0xfe})
		default:
			jsonOK(w, r)
		}
	})
	c, err := New(Config{BaseURL: srv.URL, APIKey: "ok_" + strings.Repeat("a", 64), SignToken: "sk_" + strings.Repeat("b", 64), MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, op := range Operations() {
		if op.Response == "sse" || op.Body == "form" || op.Body == "raw" {
			continue
		}
		args := CallArgs{}
		if len(op.PathParams) > 0 {
			args.Path = map[string]string{}
			for _, p := range op.PathParams {
				args.Path[p] = "v/" + p + " 1"
			}
		}
		if len(op.RequiredQuery) > 0 {
			args.Query = map[string]string{}
			for _, q := range op.RequiredQuery {
				args.Query[q] = "x"
			}
		}
		if op.Body == "json" {
			args.Body = map[string]any{"probe": true}
		}
		*seen = (*seen)[:0]
		res, err := c.Call(context.Background(), op.ID, args)
		if err != nil || res.Status != 200 || len(*seen) != 1 {
			t.Fatalf("%s: err=%v seen=%d", op.ID, err, len(*seen))
		}
		s := (*seen)[0]
		want := op.Path
		for _, p := range op.PathParams {
			want = strings.ReplaceAll(want, "{"+p+"}", url.PathEscape("v/"+p+" 1"))
		}
		if s.Method != op.Method || strings.SplitN(s.URL, "?", 2)[0] != want {
			t.Fatalf("%s: %s %s, want %s %s", op.ID, s.Method, s.URL, op.Method, want)
		}
		switch op.Auth {
		case "none":
			if s.Auth != "" {
				t.Fatalf("%s: unexpected credential", op.ID)
			}
		case "sign":
			if s.Auth != "Bearer sk_"+strings.Repeat("b", 64) {
				t.Fatalf("%s: wrong credential %q", op.ID, s.Auth)
			}
		default:
			if s.Auth != "Bearer ok_"+strings.Repeat("a", 64) {
				t.Fatalf("%s: wrong credential %q", op.ID, s.Auth)
			}
		}
		if op.Response == "binary" && string(res.Raw) != string([]byte{0x25, 0x50, 0x44, 0x46, 0xff, 0xfe}) {
			t.Fatalf("%s: binary body mangled", op.ID)
		}
		n++
	}
	if n < 350 {
		t.Fatalf("only %d operations exercised", n)
	}
}

func TestArgumentMistakesFailBeforeAnyRequest(t *testing.T) {
	srv, seen := newServer(t, jsonOK)
	c, _ := New(Config{BaseURL: srv.URL, APIKey: "ok_x"})
	ctx := context.Background()
	var one, noBody, needsBody *Operation
	for _, o := range Operations() {
		o := o
		switch {
		case one == nil && len(o.PathParams) == 1 && o.Method == "GET":
			one = &o
		case noBody == nil && o.Body == "none" && len(o.PathParams) == 0 && o.Method == "GET" && o.Auth == "ops":
			noBody = &o
		case needsBody == nil && o.BodyRequired && len(o.PathParams) == 0 && o.Auth == "ops":
			needsBody = &o
		}
	}
	expect := func(err error, kind Kind, frag string) {
		t.Helper()
		e, ok := AsError(err)
		if !ok || e.Kind != kind || !strings.Contains(e.Message, frag) {
			t.Fatalf("want %s containing %q, got %v", kind, frag, err)
		}
	}
	_, err := c.Call(ctx, one.ID, CallArgs{})
	expect(err, KindValidation, "required")
	_, err = c.Call(ctx, one.ID, CallArgs{Path: map[string]string{one.PathParams[0]: ""}})
	expect(err, KindValidation, "required")
	_, err = c.Call(ctx, one.ID, CallArgs{Path: map[string]string{one.PathParams[0]: "x", "extra": "y"}})
	expect(err, KindValidation, "unknown path parameter")
	_, err = c.Call(ctx, one.ID, CallArgs{Path: map[string]string{one.PathParams[0]: "x"}, Query: map[string]string{"nope": "1"}})
	expect(err, KindValidation, "unknown query parameter")
	_, err = c.Call(ctx, noBody.ID, CallArgs{Body: map[string]any{}})
	expect(err, KindValidation, "no request body")
	_, err = c.Call(ctx, noBody.ID, CallArgs{Headers: map[string]string{"X-Nope": "1"}})
	expect(err, KindValidation, "unknown header")
	_, err = c.Call(ctx, needsBody.ID, CallArgs{})
	expect(err, KindValidation, "body is required")
	_, err = c.Call(ctx, "noSuchOperation", CallArgs{})
	expect(err, KindValidation, "unknown operation")
	if len(*seen) != 0 {
		t.Fatalf("%d requests reached the server", len(*seen))
	}
	c2, _ := New(Config{BaseURL: srv.URL})
	_, err = c2.Call(ctx, noBody.ID, CallArgs{})
	expect(err, KindAuthentication, "API key")
}

func TestErrorShapesAndRetryPolicy(t *testing.T) {
	var hits int32
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rate":
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"error":"RATE_LIMITED","reason":"BURST","surface":"sign","retryAfterSeconds":1}`))
		case "/mgmt":
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"status":"error","error":{"code":"NOT_FOUND","message":"no such thing","details":{"id":"x"}},"requestId":"req-1"}`))
		case "/block":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"decision":"BLOCK","reason":"KEY_REVOKED","details":{"message":"revoked"},"requestId":"req-2"}`))
		case "/mfa":
			if r.Header.Get("X-QODIQA-OTP") == "123456" {
				_, _ = w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":{"code":"MFA_REQUIRED","message":"code needed"}}`))
		default:
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"SERVER_OVERLOADED","message":"busy"}}`))
		}
	})
	c, _ := New(Config{BaseURL: srv.URL, APIKey: "ok_x", MaxRetries: 2, OTPProvider: func(context.Context) (string, error) { return "123456", nil }})
	// drive the error mapper directly with synthetic operations through the same HTTP path
	op := func(method, path string) *Operation {
		return &Operation{ID: "t", Method: method, Path: path, Auth: "none", Body: "none", Response: "json"}
	}
	call := func(method, path string) (*Response, error) {
		o := op(method, path)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return c.withOTP(ctx, o, path, url.Values{}, http.Header{}, nil)
	}
	atomic.StoreInt32(&hits, 0)
	_, err := call("GET", "/rate")
	e, _ := AsError(err)
	if e == nil || e.Kind != KindRateLimit || e.Reason != "RATE_LIMITED" || e.Details["blockedBy"] != "BURST" || atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("GET 429: %+v hits=%d (want RATE_LIMITED after 3 attempts)", e, hits)
	}
	atomic.StoreInt32(&hits, 0)
	_, err = call("POST", "/rate")
	if e, _ = AsError(err); e == nil || atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("POST 429 is retried (not /ai/chat): hits=%d err=%v", hits, err)
	}
	atomic.StoreInt32(&hits, 0)
	_, err = call("POST", "/ai/chat")
	_ = err
	atomic.StoreInt32(&hits, 0)
	_, err = call("POST", "/other") // 503 SERVER_OVERLOADED on a POST: always safe to resend
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("SERVER_OVERLOADED must be retried: hits=%d err=%v", hits, err)
	}
	_, err = call("GET", "/mgmt")
	if e, _ = AsError(err); e == nil || e.Kind != KindNotFound || e.Message != "no such thing" || e.Details["id"] != "x" {
		t.Fatalf("management envelope: %+v", e)
	}
	_, err = call("GET", "/block")
	if e, _ = AsError(err); e == nil || e.Kind != KindVerification || e.Reason != "KEY_REVOKED" || e.Message != "revoked" || e.RequestID != "req-2" {
		t.Fatalf("decision envelope: %+v", e)
	}
	atomic.StoreInt32(&hits, 0)
	res, err := call("POST", "/mfa")
	if err != nil || res.Status != 200 || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("MFA step-up resend once: err=%v hits=%d", err, hits)
	}
}

func TestTimeoutAndNetworkErrors(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(600 * time.Millisecond); jsonOK(w, r) })
	c, _ := New(Config{BaseURL: srv.URL, APIKey: "ok_x", Timeout: 150 * time.Millisecond})
	var anyOp string
	for _, o := range Operations() {
		if o.Auth == "none" && len(o.PathParams) == 0 && o.Method == "GET" && o.Response == "json" && o.Body == "none" && len(o.RequiredQuery) == 0 {
			anyOp = o.ID
			break
		}
	}
	_, err := c.Call(context.Background(), anyOp, CallArgs{})
	if e, ok := AsError(err); !ok || e.Kind != KindTimeout {
		t.Fatalf("want a timeout, got %v", err)
	}
	dead, _ := New(Config{BaseURL: "http://127.0.0.1:1", Timeout: 2 * time.Second, MaxRetries: 1})
	_, err = dead.Call(context.Background(), anyOp, CallArgs{})
	if e, ok := AsError(err); !ok || e.Kind != KindNetwork {
		t.Fatalf("want a network error, got %v", err)
	}
	if _, err := New(Config{BaseURL: "ftp://x"}); err == nil {
		t.Fatal("a non-http BaseURL must be refused")
	}
	if _, err := New(Config{BaseURL: "https://user:pw@host"}); err == nil {
		t.Fatal("a BaseURL with credentials must be refused")
	}
}

func TestStreamYieldsEventsUntilDone(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if r.URL.Query().Get("cut") != "" {
			_, _ = w.Write([]byte("data: {\"n\":1}\n\n"))
			return // ends without [DONE]
		}
		_, _ = w.Write([]byte(": keep-alive\n\ndata: {\"n\":1}\n\ndata: {\"n\":2,\ndata: \"m\":3}\n\ndata: [DONE]\n\n"))
	})
	c, _ := New(Config{BaseURL: srv.URL, APIKey: "ok_x"})
	var sse string
	for _, o := range Operations() {
		if o.Response == "sse" && len(o.PathParams) == 0 {
			sse = o.ID
			break
		}
	}
	s, err := c.Stream(context.Background(), sse, CallArgs{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	re := regexp.MustCompile(`\s`)
	var got []string
	for {
		ev, err := s.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(ev)
		got = append(got, re.ReplaceAllString(string(b), ""))
	}
	if strings.Join(got, "|") != `{"n":1}|{"m":3,"n":2}` {
		t.Fatalf("events: %v", got)
	}
	if _, err := c.Call(context.Background(), sse, CallArgs{}); err == nil {
		t.Fatal("Call on a streaming operation must be refused")
	}
}
