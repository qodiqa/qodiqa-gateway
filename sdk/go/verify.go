package qodiqa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Domain tags of the protocol (a domain-separated hash is SHA-256(utf8(tag) || utf8(canonical)), no separator byte).
const (
	DomainArtifact          = "QODIQA::ARTIFACT::V1"
	DomainTransparencyEntry = "QODIQA::TRANSPARENCY::V1"
	DomainTransparencyRoot  = "QODIQA::TRANSPARENCY_ROOT::V1"
	DomainRequest           = "QODIQA::REQUEST::V1"
	DomainPolicy            = "QODIQA::POLICY::V1"
)

// DomainHash returns SHA-256(tag || canonical).
func DomainHash(tag, canonical string) []byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte(canonical))
	return h.Sum(nil)
}

// DomainHashHex is DomainHash as lower-case hex.
func DomainHashHex(tag, canonical string) string {
	return hex.EncodeToString(DomainHash(tag, canonical))
}

// EnvelopeHash is the hash an artifact signature covers: the domain hash of the canonical {expiry, payload, publicKeyId, timestamp}.
func EnvelopeHash(artifact map[string]any) ([]byte, error) {
	c, err := Canonicalize(map[string]any{
		"expiry": artifact["expiry"], "payload": artifact["payload"], "publicKeyId": artifact["publicKeyId"], "timestamp": artifact["timestamp"],
	})
	if err != nil {
		return nil, err
	}
	return DomainHash(DomainArtifact, c), nil
}

// VerifyEd25519 checks a base64 signature over a 32-byte hash with an SPKI DER public key. Any malformed input is simply "not valid".
func VerifyEd25519(hash []byte, signatureB64 string, spkiDER []byte) bool {
	if len(hash) != 32 || len(spkiDER) == 0 {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return false
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(ed, hash, sig)
}

// ResolvedKey is a public key as a KeyProvider returns it.
type ResolvedKey struct {
	PubDER []byte
	Status string // active, deprecated, revoked, archived, ...
	Source string // live, cached, ...
}

// KeyProvider resolves a key id to a public key; (nil, nil) means "unknown key".
type KeyProvider interface {
	PublicKey(keyID string) (*ResolvedKey, error)
}

// StaticKeyEntry is one key of a static trust bundle (the shape of the shared vector files).
type StaticKeyEntry struct {
	KeyID     string
	PublicKey string // base64 SPKI DER
	Status    string
}

// StaticKeyProvider is a trust bundle held in memory.
type StaticKeyProvider struct{ keys map[string]*ResolvedKey }

// NewStaticKeyProvider builds a provider; an entry whose key is not valid base64 is rejected.
func NewStaticKeyProvider(entries []StaticKeyEntry) (*StaticKeyProvider, error) {
	p := &StaticKeyProvider{keys: map[string]*ResolvedKey{}}
	for _, e := range entries {
		der, err := base64.StdEncoding.DecodeString(e.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("key %q: public key is not base64: %w", e.KeyID, err)
		}
		p.keys[e.KeyID] = &ResolvedKey{PubDER: der, Status: e.Status, Source: "live"}
	}
	return p, nil
}

// PublicKey implements KeyProvider.
func (p *StaticKeyProvider) PublicKey(keyID string) (*ResolvedKey, error) { return p.keys[keyID], nil }

// ArtifactVerification is the result of ArtifactVerifier.Verify (field meanings as in the JavaScript and Python SDKs).
type ArtifactVerification struct {
	VerificationStatus   string // valid | invalid | error
	SignatureValid       bool
	PayloadHashValid     bool
	CanonicalizationOK   bool
	KeyValid             bool
	KeyID                string
	KeyStatus            string
	KeySource            string
	ExpiryValid          bool
	TimestampValid       bool
	TransparencyVerified string // verified | failed | unavailable
	TransparencyDetail   *TransparencyDetail
	Errors               []string
	Warnings             []string
	FailedStage          string // "" when valid
	VerifiedAt           int64
}

// ArtifactVerifierOptions configures an ArtifactVerifier.
type ArtifactVerifierOptions struct {
	Keys                KeyProvider
	TransparencyKeys    KeyProvider
	ClockToleranceMs    int64
	RequireTransparency bool
	NowMs               func() int64 // default: the system clock
}

// ArtifactVerifier verifies artifacts offline against a trust bundle.
type ArtifactVerifier struct{ o ArtifactVerifierOptions }

// NewArtifactVerifier validates the options.
func NewArtifactVerifier(o ArtifactVerifierOptions) (*ArtifactVerifier, error) {
	if o.Keys == nil {
		return nil, fmt.Errorf("ArtifactVerifier requires a Keys provider")
	}
	if o.RequireTransparency && o.TransparencyKeys == nil {
		return nil, fmt.Errorf("RequireTransparency needs TransparencyKeys")
	}
	if o.NowMs == nil {
		o.NowMs = nowMs
	}
	return &ArtifactVerifier{o: o}, nil
}

var (
	artifactFields = []string{"expiry", "payload", "publicKeyId", "signature", "timestamp"}
	base64RE       = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
)

const maxSafeInteger = 9007199254740991

// safePositiveInt reports whether v is a JSON number that, read as a JavaScript double, is a positive safe integer (like Number.isSafeInteger: 1e3 and 1.0 are, 1.5 and 2^53 are not).
func safePositiveInt(v any) (int64, bool) {
	var f float64
	switch t := v.(type) {
	case json.Number:
		x, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return 0, false
		}
		f = x
	case float64:
		f = t
	default:
		return 0, false
	}
	if f != math.Floor(f) || f <= 0 || f > maxSafeInteger {
		return 0, false
	}
	return int64(f), true
}

func nowMs() int64 { return time.Now().UnixMilli() }

// Verify checks a decoded artifact (ParseJSON output). transparencyProof may be nil.
func (v *ArtifactVerifier) Verify(artifact any, transparencyProof map[string]any) *ArtifactVerification {
	now := v.o.NowMs()
	r := &ArtifactVerification{VerificationStatus: "invalid", TransparencyVerified: "unavailable", VerifiedAt: now}
	fail := func(stage, msg string) *ArtifactVerification {
		r.FailedStage = stage
		r.Errors = append(r.Errors, msg)
		return r
	}
	a, ok := artifact.(map[string]any)
	if !ok {
		return fail("STRUCTURE", "Artifact must be a plain object.")
	}
	for k := range a {
		known := false
		for _, f := range artifactFields {
			if k == f {
				known = true
			}
		}
		if !known {
			return fail("STRUCTURE", fmt.Sprintf("Unexpected field %q is not part of the artifact envelope.", k))
		}
	}
	for _, f := range artifactFields {
		if _, present := a[f]; !present {
			return fail("STRUCTURE", fmt.Sprintf("Missing required field %q.", f))
		}
	}
	if _, ok := a["payload"].(map[string]any); !ok {
		return fail("STRUCTURE", "Artifact payload must be a plain object.")
	}
	ts, ok := safePositiveInt(a["timestamp"])
	if !ok {
		return fail("STRUCTURE", "Artifact timestamp must be a positive safe integer (Unix ms).")
	}
	exp, ok := safePositiveInt(a["expiry"])
	if !ok {
		return fail("STRUCTURE", "Artifact expiry must be a positive safe integer (Unix ms).")
	}
	if ts >= exp {
		return fail("STRUCTURE", "Artifact expiry must be greater than its timestamp.")
	}
	sig, ok := a["signature"].(string)
	if !ok || !base64RE.MatchString(sig) {
		return fail("STRUCTURE", "Artifact signature must be base64 decoding to exactly 64 bytes.")
	}
	if raw, err := base64.StdEncoding.DecodeString(sig); err != nil || len(raw) != 64 {
		return fail("STRUCTURE", "Artifact signature must be base64 decoding to exactly 64 bytes.")
	}
	keyID, ok := a["publicKeyId"].(string)
	if !ok || strings.TrimSpace(keyID) == "" {
		return fail("STRUCTURE", "Artifact publicKeyId must be a non-empty string.")
	}
	hash, err := EnvelopeHash(a)
	if err != nil {
		return fail("CANONICALIZATION", "Envelope canonicalization failed: "+err.Error())
	}
	r.CanonicalizationOK, r.PayloadHashValid = true, true

	r.KeyID = keyID
	key, err := v.o.Keys.PublicKey(keyID)
	if err != nil {
		r.VerificationStatus = "error"
		return fail("KEY_RESOLUTION", fmt.Sprintf("Key provider failed to resolve %q: %v", keyID, err))
	}
	if key == nil {
		return fail("KEY_RESOLUTION", fmt.Sprintf("Unknown key id %q.", keyID))
	}
	r.KeyStatus, r.KeySource = key.Status, key.Source
	if r.KeySource == "" {
		r.KeySource = "live"
	}
	r.KeyValid = key.Status == "active" || key.Status == "deprecated"
	if !r.KeyValid {
		return fail("KEY_RESOLUTION", fmt.Sprintf("Key %q has status %q and cannot verify.", keyID, key.Status))
	}
	r.TimestampValid = ts <= now+v.o.ClockToleranceMs
	if !r.TimestampValid {
		return fail("FUTURE_TIMESTAMP", "Artifact timestamp is in the future.")
	}
	r.ExpiryValid = now-v.o.ClockToleranceMs < exp
	if !r.ExpiryValid {
		return fail("EXPIRED", "Artifact has expired.")
	}
	r.SignatureValid = VerifyEd25519(hash, sig, key.PubDER)
	if !r.SignatureValid {
		return fail("INVALID_SIGNATURE", "Ed25519 signature verification failed.")
	}
	switch {
	case transparencyProof != nil:
		if v.o.TransparencyKeys == nil {
			r.Warnings = append(r.Warnings, "A transparencyProof was supplied but no TransparencyKeys provider is configured; skipping transparency verification.")
		} else {
			d := VerifyTransparencyProof(transparencyProof, v.o.TransparencyKeys)
			r.TransparencyDetail = d
			if d.AllPassed() {
				r.TransparencyVerified = "verified"
			} else {
				r.TransparencyVerified = "failed"
				return fail("TRANSPARENCY", "Transparency inclusion proof verification failed.")
			}
		}
	case v.o.RequireTransparency:
		return fail("TRANSPARENCY", "Transparency verification is required but no transparencyProof was supplied.")
	}
	r.VerificationStatus = "valid"
	return r
}
