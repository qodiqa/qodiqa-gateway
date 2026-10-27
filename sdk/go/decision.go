package qodiqa

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"regexp"
	"strings"
	"time"
)

// This file is the offline form of the gateway's own decision procedure for a V1 artifact (docs/protocol/QODIQA-PROTOCOL.md, "artifact verification"): the same checks in the same order,
// with key lifecycle (active / deprecated / revoked / archived) and the time limits of the protocol. It is pinned by the shared vectors (conformance_test.go), like the two other
// independent implementations (scripts/protocol/verify-vectors.js and verify_vectors.py).

// Limits are the protocol's time limits in milliseconds.
type Limits struct {
	FutureSkewMs       int64 // an artifact may be at most this far in the future
	MaxArtifactAgeMs   int64 // and at most this old
	DeprecatedWindowMs int64 // a deprecated key still verifies for this long after its deprecation
}

// DefaultLimits are the protocol defaults (5 s skew, 60 s age, 65 s deprecation window).
var DefaultLimits = Limits{FutureSkewMs: 5000, MaxArtifactAgeMs: 60000, DeprecatedWindowMs: 65000}

// KeyTimeline is the lifecycle of one signing key.
type KeyTimeline struct {
	Status       string // active | deprecated | revoked | archived
	ActivatedAt  string // RFC 3339, "" when unknown
	DeprecatedAt string
}

// TimedKey is a trust-bundle key with its lifecycle.
type TimedKey struct {
	PubDER   []byte
	Timeline KeyTimeline
}

// Decision is the outcome of the procedure: EXECUTE (all checks passed) or BLOCK with a reason.
type Decision struct {
	Decision string
	Reason   string
}

var sigRE = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==$`)

func parseMs(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, false
	}
	return t.UnixMilli(), true
}

// DecideArtifact runs the protocol's verification of a decoded artifact at time nowMs against a keyed trust bundle.
func DecideArtifact(artifact any, keys map[string]TimedKey, nowMs int64, lim Limits) Decision {
	block := func(reason string) Decision { return Decision{"BLOCK", reason} }
	a, ok := artifact.(map[string]any)
	if !ok {
		return block("INVALID_ARTIFACT")
	}
	for k := range a {
		known := false
		for _, f := range artifactFields {
			known = known || k == f
		}
		if !known {
			return block("INVALID_ARTIFACT")
		}
	}
	for _, f := range artifactFields {
		if _, p := a[f]; !p {
			return block("INVALID_ARTIFACT")
		}
	}
	if _, ok := a["payload"].(map[string]any); !ok {
		return block("INVALID_ARTIFACT")
	}
	ts, okT := safePositiveInt(a["timestamp"])
	exp, okE := safePositiveInt(a["expiry"])
	if !okT || !okE {
		return block("INVALID_ARTIFACT")
	}
	sig, ok := a["signature"].(string)
	if !ok {
		return block("INVALID_ARTIFACT")
	}
	if raw, err := base64.StdEncoding.DecodeString(sig); !sigRE.MatchString(sig) || err != nil || base64.StdEncoding.EncodeToString(raw) != sig {
		return block("INVALID_SIGNATURE")
	}
	keyID, ok := a["publicKeyId"].(string)
	if !ok || strings.TrimSpace(keyID) == "" {
		return block("INVALID_ARTIFACT")
	}
	key, known := keys[keyID]
	hash, err := EnvelopeHash(a)
	if err != nil {
		return block("INVALID_ARTIFACT")
	}
	pub, perr := x509.ParsePKIXPublicKey(key.PubDER)
	edKey, isEd := pub.(ed25519.PublicKey)
	rawSig, _ := base64.StdEncoding.DecodeString(sig)
	if !known || perr != nil || !isEd || !ed25519.Verify(edKey, hash, rawSig) {
		return block("INVALID_SIGNATURE")
	}
	if ts >= exp {
		return block("INVALID_ARTIFACT")
	}
	if ts > nowMs+lim.FutureSkewMs {
		return block("FUTURE_TIMESTAMP")
	}
	if nowMs >= exp {
		return block("EXPIRED")
	}
	if nowMs-ts > lim.MaxArtifactAgeMs {
		return block("TIME_SKEW_EXCEEDED")
	}
	t := key.Timeline
	switch t.Status {
	case "revoked":
		return block("KEY_REVOKED")
	case "archived":
		return block("KEY_ARCHIVED")
	case "deprecated":
		dep, ok := parseMs(t.DeprecatedAt)
		if !ok || ts >= dep || nowMs >= dep+lim.DeprecatedWindowMs {
			return block("KEY_DEPRECATED")
		}
		return Decision{"EXECUTE", "ALL_CHECKS_PASSED"}
	case "active":
		if act, ok := parseMs(t.ActivatedAt); ok && ts < act-lim.FutureSkewMs {
			return block("KEY_NOT_YET_ACTIVE")
		}
		return Decision{"EXECUTE", "ALL_CHECKS_PASSED"}
	}
	return block("KEY_STATUS_UNKNOWN")
}

// RequestHash binds a request to an artifact: hex(SHA-256("QODIQA::REQUEST::V1" || canonical({body, method: UPPER(method), path}))).
func RequestHash(method, path string, body any) (string, error) {
	c, err := Canonicalize(map[string]any{"body": body, "method": strings.ToUpper(method), "path": path})
	if err != nil {
		return "", err
	}
	return DomainHashHex(DomainRequest, c), nil
}

// PolicyHash is hex(SHA-256("QODIQA::POLICY::V1" || canonical(policies with every "_"-prefixed key removed, recursively))).
func PolicyHash(policies any) (string, error) {
	c, err := Canonicalize(stripUnderscore(policies))
	if err != nil {
		return "", err
	}
	return DomainHashHex(DomainPolicy, c), nil
}

func stripUnderscore(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = stripUnderscore(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if strings.HasPrefix(k, "_") && k != "__proto__" {
				continue
			}
			out[k] = stripUnderscore(x)
		}
		return out
	}
	return v
}
