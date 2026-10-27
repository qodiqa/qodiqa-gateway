// Command smoke runs the Go SDK against a RUNNING gateway: sign, offline verification, chat, a generic operation and the error mapping.
// Env: QODIQA_BASE_URL, QODIQA_SIGN_TOKEN (sk_...), QODIQA_API_KEY (ok_...). One line per check; exit 1 if any failed.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	qodiqa "github.com/qodiqa/qodiqa-go"
)

var failed bool

func report(ok bool, name, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failed = true
	}
	if len(detail) > 80 {
		detail = detail[:80]
	}
	fmt.Printf("%s  go: %s  (%s)\n", status, name, detail)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := qodiqa.New(qodiqa.Config{BaseURL: os.Getenv("QODIQA_BASE_URL"), APIKey: os.Getenv("QODIQA_API_KEY"), SignToken: os.Getenv("QODIQA_SIGN_TOKEN"), MaxRetries: 1})
	if err != nil {
		fmt.Println("FAIL  go: client:", err)
		os.Exit(1)
	}

	res, err := c.Call(ctx, "getReadiness", qodiqa.CallArgs{})
	ready := false
	if err == nil {
		if v, e := res.JSON(); e == nil {
			if m, ok := v.(map[string]any); ok {
				ready, _ = m["ready"].(bool)
			}
		}
	}
	report(err == nil && ready, "ready", fmt.Sprint(err))

	var entries []qodiqa.StaticKeyEntry
	res, err = c.Call(ctx, "discoverPublicKeys", qodiqa.CallArgs{})
	if err == nil {
		v, _ := res.JSON()
		data := v.(map[string]any)["data"].(map[string]any)
		for _, k := range data["keys"].([]any) {
			m := k.(map[string]any)
			entries = append(entries, qodiqa.StaticKeyEntry{KeyID: m["keyId"].(string), PublicKey: m["publicKey"].(string), Status: m["status"].(string)})
		}
	}
	report(err == nil && len(entries) > 0, "public keys", fmt.Sprintf("%d keys %v", len(entries), err))

	body := map[string]any{"prompt": "go sdk"}
	res, err = c.Call(ctx, "signRequest", qodiqa.CallArgs{Body: map[string]any{"request": map[string]any{"method": "POST", "path": "/ai/chat", "body": body}, "payload": map[string]any{"userId": "smoke-go"}, "ttl": 60000}})
	var artifact any
	var artifactID string
	if err == nil {
		v, _ := res.JSON()
		m := v.(map[string]any)
		artifact = m["artifact"]
		artifactID, _ = m["artifactId"].(string)
	}
	report(err == nil && artifact != nil, "sign", artifactID)

	if artifact != nil {
		kp, _ := qodiqa.NewStaticKeyProvider(entries)
		ver, _ := qodiqa.NewArtifactVerifier(qodiqa.ArtifactVerifierOptions{Keys: kp, ClockToleranceMs: 5000})
		r := ver.Verify(artifact, nil)
		report(r.VerificationStatus == "valid", "offline verification of the artifact against /public-keys", r.VerificationStatus+" "+r.FailedStage)

		want, _ := qodiqa.RequestHash("POST", "/ai/chat", body)
		got, _ := artifact.(map[string]any)["payload"].(map[string]any)["requestHash"].(string)
		report(got == want, "request hash binding (artifact guard input)", got)

		raw, _ := json.Marshal(artifact)
		art := base64.StdEncoding.EncodeToString(raw)
		chatRes, err := c.Call(ctx, "executeAiChat", qodiqa.CallArgs{Body: body, Headers: map[string]string{"x-qodiqa-artifact": art}})
		okChat := false
		detail := fmt.Sprint(err)
		if err == nil {
			v, _ := chatRes.JSON()
			m := v.(map[string]any)
			text, _ := m["response"].(string)
			okChat = m["decision"] == "EXECUTE" && strings.HasPrefix(text, "[sandbox] go sdk")
			detail = text
		}
		report(okChat, "chat through the sandbox provider", detail)
	}

	_, err = c.Call(ctx, "listAlerts", qodiqa.CallArgs{})
	report(err == nil, "generic operation: Call(listAlerts) with the operator key", fmt.Sprint(err))

	bad, _ := qodiqa.New(qodiqa.Config{BaseURL: os.Getenv("QODIQA_BASE_URL"), SignToken: "sk_" + strings.Repeat("0", 64), MaxRetries: -1})
	_, err = bad.Call(ctx, "signRequest", qodiqa.CallArgs{Body: map[string]any{"request": map[string]any{"method": "POST", "path": "/ai/chat", "body": map[string]any{}}}})
	e, ok := qodiqa.AsError(err)
	report(ok && e.Kind == qodiqa.KindAuthentication, "error mapping: a wrong signing key is an authentication error", fmt.Sprint(err))

	if failed {
		os.Exit(1)
	}
}
