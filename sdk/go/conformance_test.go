package qodiqa

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Conformance against the shared, language-neutral vectors (copied byte-for-byte from docs/protocol/vectors and test-vectors by scripts/sdk/generate-operations.js;
// `npm run sdk:check` fails when the copies differ). The same vectors are verified by the JavaScript SDK, the Python SDK, scripts/protocol/verify-vectors.js,
// scripts/protocol/verify_vectors.py and the Java SDK; nothing is regenerated here.

func loadVectors(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("cannot read the vector file %s: %v", name, err)
	}
	v, err := ParseJSON(raw)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", name, err)
	}
	return v.(map[string]any)
}

func arr(v any) []any          { return v.([]any) }
func obj(v any) map[string]any { return v.(map[string]any) }
func str(v any) string         { s, _ := v.(string); return s }

func num(t *testing.T, v any) int64 {
	t.Helper()
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("not a number: %v", v)
	}
	i, err := n.Int64()
	if err != nil {
		t.Fatalf("not an integer: %v", n)
	}
	return i
}

func TestProtocolV1Canonicalization(t *testing.T) {
	v := loadVectors(t, "qodiqa-protocol-vectors.json")
	canon := obj(v["canonicalization"])
	cases := arr(canon["valid"])
	if len(cases) < 8 {
		t.Fatalf("expected at least 8 canonicalization vectors, got %d", len(cases))
	}
	for _, c := range cases {
		c := obj(c)
		t.Run(str(c["name"]), func(t *testing.T) {
			got, err := Canonicalize(c["input"])
			if err != nil || got != str(c["canonical"]) {
				t.Fatalf("got %q (%v), want %q", got, err, c["canonical"])
			}
		})
	}
	t.Run("forbidden keys", func(t *testing.T) {
		for _, k := range []string{"__proto__", "constructor", "prototype"} {
			_, err := Canonicalize(map[string]any{k: json.Number("1")})
			if ce, ok := err.(*CanonicalizationError); !ok || ce.Code != "FORBIDDEN_KEY" {
				t.Fatalf("%s: want FORBIDDEN_KEY, got %v", k, err)
			}
		}
	})
	t.Run("depth over 1000", func(t *testing.T) {
		var x any = json.Number("1")
		for i := 0; i < 1100; i++ {
			x = map[string]any{"a": x}
		}
		if _, err := Canonicalize(x); err == nil || err.(*CanonicalizationError).Code != "MAX_DEPTH_EXCEEDED" {
			t.Fatalf("want MAX_DEPTH_EXCEEDED, got %v", err)
		}
	})
	t.Run("unsupported type", func(t *testing.T) {
		if _, err := Canonicalize(map[string]any{"f": func() {}}); err == nil || err.(*CanonicalizationError).Code != "UNSUPPORTED_TYPE" {
			t.Fatalf("want UNSUPPORTED_TYPE, got %v", err)
		}
	})
	t.Run("non finite", func(t *testing.T) {
		if _, err := Canonicalize(map[string]any{"x": json.Number("1e999")}); err == nil || err.(*CanonicalizationError).Code != "NON_FINITE_NUMBER" {
			t.Fatalf("want NON_FINITE_NUMBER, got %v", err)
		}
	})
}

func TestJSNumberFormatting(t *testing.T) {
	// ECMAScript Number.prototype.toString, the shapes that matter for canonical output
	cases := map[string]string{
		"0": "0", "-0": "0", "1": "1", "-1": "-1", "1.5": "1.5", "0.1": "0.1", "100": "100", "1e21": "1e+21", "1e-7": "1e-7", "123456789012345680000": "123456789012345680000",
		"0.000001": "0.000001", "1.7976931348623157e308": "1.7976931348623157e+308", "5e-324": "5e-324", "9007199254740991": "9007199254740991", "0.30000000000000004": "0.30000000000000004",
		"1e20": "100000000000000000000", "-1.25e-10": "-1.25e-10",
	}
	for in, want := range cases {
		got, err := Canonicalize(json.Number(in))
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", in, got, err, want)
		}
	}
}

func TestProtocolV1DomainTagsArtifactsRequestAndPolicy(t *testing.T) {
	v := loadVectors(t, "qodiqa-protocol-vectors.json")
	dt := obj(v["domainTags"])
	sample := str(dt["sampleCanonical"])
	for _, x := range arr(dt["tags"]) {
		x := obj(x)
		if got := DomainHashHex(str(x["tag"]), sample); got != str(x["digestHex"]) {
			t.Errorf("domain tag %s: got %s want %s", x["tag"], got, x["digestHex"])
		}
	}
	signer := obj(v["testKeys"])
	spki, _ := base64.StdEncoding.DecodeString(str(signer["signerPublicKeySpkiB64"]))
	for _, a := range arr(v["artifacts"]) {
		a := obj(a)
		art := obj(a["artifact"])
		c, err := Canonicalize(map[string]any{"expiry": art["expiry"], "payload": art["payload"], "publicKeyId": art["publicKeyId"], "timestamp": art["timestamp"]})
		h := DomainHash(DomainArtifact, c)
		if err != nil || c != str(a["envelopeCanonical"]) || toHex(h) != str(a["envelopeHashHex"]) || !VerifyEd25519(h, str(art["signature"]), spki) {
			t.Errorf("artifact %s: envelope/hash/signature mismatch (%v)", a["name"], err)
		}
	}
	for _, r := range arr(obj(v["requestBinding"])["hashes"]) {
		r := obj(r)
		req := obj(r["request"])
		got, err := RequestHash(str(req["method"]), str(req["path"]), req["body"])
		if err != nil || got != str(r["requestHashHex"]) {
			t.Errorf("request %s: got %s want %s (%v)", r["name"], got, r["requestHashHex"], err)
		}
	}
	for _, c := range arr(obj(v["policyHash"])["cases"]) {
		c := obj(c)
		got, err := PolicyHash(c["policies"])
		if err != nil || got != str(c["policyHashHex"]) {
			t.Errorf("policy %s: got %s want %s (%v)", c["name"], got, c["policyHashHex"], err)
		}
	}
}

func toHex(b []byte) string {
	const hexd = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(hexd[x>>4])
		sb.WriteByte(hexd[x&0xf])
	}
	return sb.String()
}

func TestProtocolV1VerificationDecisions(t *testing.T) {
	v := loadVectors(t, "qodiqa-protocol-vectors.json")
	ver := obj(v["verification"])
	keys := map[string]TimedKey{}
	for _, k := range arr(ver["keys"]) {
		k := obj(k)
		der, _ := base64.StdEncoding.DecodeString(str(k["publicKeySpkiB64"]))
		tl := obj(k["timeline"])
		keys[str(k["publicKeyId"])] = TimedKey{PubDER: der, Timeline: KeyTimeline{Status: str(tl["status"]), ActivatedAt: str(tl["activatedAt"]), DeprecatedAt: str(tl["deprecatedAt"])}}
	}
	lim := obj(ver["limits"])
	limits := Limits{FutureSkewMs: num(t, lim["futureSkewMs"]), MaxArtifactAgeMs: num(t, lim["maxArtifactAgeMs"]), DeprecatedWindowMs: num(t, lim["deprecatedWindowMs"])}
	now := num(t, ver["nowMs"])
	cases := arr(ver["cases"])
	if len(cases) < 21 {
		t.Fatalf("expected the 21 verification vectors, got %d", len(cases))
	}
	for _, c := range cases {
		c := obj(c)
		t.Run(str(c["name"]), func(t *testing.T) {
			d := DecideArtifact(c["artifact"], keys, now, limits)
			exp := obj(c["expected"])
			if d.Decision != str(exp["decision"]) || d.Reason != str(exp["reason"]) {
				t.Fatalf("got %s/%s, want %s/%s", d.Decision, d.Reason, exp["decision"], exp["reason"])
			}
		})
	}
}

func keyEntries(t *testing.T, v any) []StaticKeyEntry {
	t.Helper()
	var out []StaticKeyEntry
	for _, k := range arr(v) {
		k := obj(k)
		out = append(out, StaticKeyEntry{KeyID: str(k["keyId"]), PublicKey: str(k["publicKey"]), Status: str(k["status"])})
	}
	return out
}

func TestArtifactVectors(t *testing.T) {
	f := loadVectors(t, "artifact-v1.json")
	vs := arr(f["artifactVectors"])
	if len(vs) != int(num(t, obj(f["vectorCount"])["artifact"])) {
		t.Fatalf("vectorCount.artifact does not match")
	}
	for _, v := range vs {
		v := obj(v)
		t.Run(str(v["id"]), func(t *testing.T) {
			kp, err := NewStaticKeyProvider(keyEntries(t, v["keySet"]))
			if err != nil {
				t.Fatal(err)
			}
			at := num(t, v["verifyAt"])
			ver, _ := NewArtifactVerifier(ArtifactVerifierOptions{Keys: kp, ClockToleranceMs: num(t, v["clockToleranceMs"]), NowMs: func() int64 { return at }})
			r := ver.Verify(v["artifact"], nil)
			exp := obj(v["expected"])
			check := func(name string, got any) {
				if want, ok := exp[name]; ok && want != got {
					t.Errorf("%s: got %v want %v", name, got, want)
				}
			}
			check("verificationStatus", r.VerificationStatus)
			check("signatureValid", r.SignatureValid)
			check("payloadHashValid", r.PayloadHashValid)
			check("canonicalizationValid", r.CanonicalizationOK)
			check("keyValid", r.KeyValid)
			check("timestampValid", r.TimestampValid)
			check("expiryValid", r.ExpiryValid)
			if ks, ok := exp["keyStatus"]; ok && ks != nil {
				check("keyStatus", r.KeyStatus)
			}
			if fs, ok := exp["failedStage"]; ok {
				got := any(r.FailedStage)
				if r.FailedStage == "" {
					got = nil
				}
				if fs != got {
					t.Errorf("failedStage: got %v want %v", got, fs)
				}
			}
		})
	}
}

func TestTransparencyVectors(t *testing.T) {
	f := loadVectors(t, "artifact-v1.json")
	vs := arr(f["transparencyVectors"])
	if len(vs) != int(num(t, obj(f["vectorCount"])["transparency"])) {
		t.Fatalf("vectorCount.transparency does not match")
	}
	first := obj(arr(f["artifactVectors"])[0])
	for _, v := range vs {
		v := obj(v)
		t.Run(str(v["id"]), func(t *testing.T) {
			tk, err := NewStaticKeyProvider(keyEntries(t, v["transparencyKeySet"]))
			if err != nil {
				t.Fatal(err)
			}
			exp := obj(v["expected"])
			if v["proof"] == nil {
				kp, _ := NewStaticKeyProvider(keyEntries(t, first["keySet"]))
				at := num(t, first["verifyAt"])
				ver, _ := NewArtifactVerifier(ArtifactVerifierOptions{Keys: kp, TransparencyKeys: tk, NowMs: func() int64 { return at }})
				if r := ver.Verify(first["artifact"], nil); r.TransparencyVerified != str(exp["transparencyVerified"]) {
					t.Fatalf("got %s want %s", r.TransparencyVerified, exp["transparencyVerified"])
				}
				return
			}
			d := VerifyTransparencyProof(obj(v["proof"]), tk)
			verified := "failed"
			if d.AllPassed() {
				verified = "verified"
			}
			got := map[string]any{
				"transparencyVerified": verified, "entryHashValid": d.EntryHashValid, "merklePathValid": d.MerklePathValid, "leafIndexValid": d.LeafIndexValid,
				"keyValid": d.KeyValid, "entrySignatureValid": d.EntrySignatureValid, "rootSignatureValid": d.RootSignatureValid,
			}
			for k, want := range exp {
				if got[k] != want {
					t.Errorf("%s: got %v want %v", k, got[k], want)
				}
			}
		})
	}
}

func TestArtifactVerifierWithTransparencyProofEndToEnd(t *testing.T) {
	f := loadVectors(t, "artifact-v1.json")
	// the genuine artifact + the genuine proof are separate vectors (the proof is for another artifact id), so only the wiring is exercised: a failing proof fails the verification
	first := obj(arr(f["artifactVectors"])[0])
	tv := obj(arr(f["transparencyVectors"])[1]) // wrong-merkle-root
	kp, _ := NewStaticKeyProvider(keyEntries(t, first["keySet"]))
	tk, _ := NewStaticKeyProvider(keyEntries(t, tv["transparencyKeySet"]))
	at := num(t, first["verifyAt"])
	ver, _ := NewArtifactVerifier(ArtifactVerifierOptions{Keys: kp, TransparencyKeys: tk, NowMs: func() int64 { return at }})
	r := ver.Verify(first["artifact"], obj(tv["proof"]))
	if r.VerificationStatus != "invalid" || r.FailedStage != "TRANSPARENCY" || r.TransparencyVerified != "failed" {
		t.Fatalf("got %+v", r)
	}
	req, _ := NewArtifactVerifier(ArtifactVerifierOptions{Keys: kp, TransparencyKeys: tk, RequireTransparency: true, NowMs: func() int64 { return at }})
	if r := req.Verify(first["artifact"], nil); r.FailedStage != "TRANSPARENCY" {
		t.Fatalf("required transparency without a proof must fail, got %+v", r)
	}
	if _, err := NewArtifactVerifier(ArtifactVerifierOptions{Keys: kp, RequireTransparency: true}); err == nil {
		t.Fatal("RequireTransparency without TransparencyKeys must be refused")
	}
}

func TestVerifierNeverPanicsOnHostileInput(t *testing.T) {
	kp, _ := NewStaticKeyProvider(nil)
	ver, _ := NewArtifactVerifier(ArtifactVerifierOptions{Keys: kp, NowMs: func() int64 { return 1 }})
	for _, in := range []string{`null`, `[]`, `"x"`, `{}`, `{"expiry":1,"payload":[],"publicKeyId":"k","signature":"x","timestamp":0}`,
		`{"expiry":1e400,"payload":{},"publicKeyId":"k","signature":"x","timestamp":1}`, `{"expiry":2,"payload":{"a":{"__proto__":1}},"publicKeyId":"k","signature":"AAAA","timestamp":1}`} {
		v, err := ParseJSON([]byte(in))
		if err != nil {
			continue
		}
		if r := ver.Verify(v, nil); r.VerificationStatus == "valid" {
			t.Errorf("%s verified", in)
		}
		_ = VerifyTransparencyProof(map[string]any{"proofVersion": "2", "proofType": "TRANSPARENCY_INCLUSION", "entry": v, "root": v, "proof": v}, kp)
	}
}
