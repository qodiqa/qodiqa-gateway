package dev.qodiqa.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.qodiqa.sdk.QodiqaClient.CallArgs;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Runs the Java SDK against a RUNNING gateway: sign, offline verification, chat, a generic operation and the error mapping.
 * Env: QODIQA_BASE_URL, QODIQA_SIGN_TOKEN (sk_...), QODIQA_API_KEY (ok_...). One line per check; exit code 1 if any failed.
 * Not a unit test (it needs a gateway): run it with {@code java -cp target/classes:target/test-classes:<jackson> dev.qodiqa.sdk.Smoke}.
 */
public final class Smoke {
  private static boolean failed;

  private static void report(boolean ok, String name, String detail) {
    if (!ok) failed = true;
    String d = detail == null ? "" : detail.length() > 80 ? detail.substring(0, 80) : detail;
    System.out.println((ok ? "PASS" : "FAIL") + "  java: " + name + "  (" + d + ")");
  }

  public static void main(String[] args) throws Exception {
    String base = System.getenv("QODIQA_BASE_URL");
    QodiqaClient c = QodiqaClient.builder().baseUrl(base).apiKey(System.getenv("QODIQA_API_KEY")).signToken(System.getenv("QODIQA_SIGN_TOKEN")).maxRetries(1).timeout(Duration.ofSeconds(30)).build();

    JsonNode ready = c.call("getReadiness", CallArgs.none()).json();
    report(ready.path("ready").asBoolean(false), "ready", ready.toString());

    JsonNode keysDoc = c.call("discoverPublicKeys", CallArgs.none()).json();
    JsonNode keys = keysDoc.path("data").path("keys");
    report(keys.isArray() && keys.size() > 0, "public keys", keys.size() + " keys");

    ObjectNode body = JsonNodeFactory.instance.objectNode().put("prompt", "java sdk");
    ObjectNode req = JsonNodeFactory.instance.objectNode();
    req.putObject("request").put("method", "POST").put("path", "/ai/chat").set("body", body);
    req.putObject("payload").put("userId", "smoke-java");
    req.put("ttl", 60000);
    JsonNode signed = c.call("signRequest", new CallArgs(null, null, null, req)).json();
    JsonNode artifact = signed.get("artifact");
    report(artifact != null && artifact.isObject(), "sign", signed.path("artifactId").asText());

    Verify.ArtifactVerification v = new Verify.ArtifactVerifier(new Verify.StaticKeyProvider(keys), null, 5000, false, null).verify(artifact, null);
    report("valid".equals(v.verificationStatus), "offline verification of the artifact against /public-keys", v.verificationStatus + " " + v.failedStage);

    String want = Verify.requestHash("POST", "/ai/chat", body);
    report(want.equals(artifact.path("payload").path("requestHash").asText()), "request hash binding (artifact guard input)", want);

    String b64 = Base64.getEncoder().encodeToString(artifact.toString().getBytes(StandardCharsets.UTF_8));
    JsonNode chat = c.call("executeAiChat", new CallArgs(null, null, Map.of("x-qodiqa-artifact", b64), body)).json();
    report("EXECUTE".equals(chat.path("decision").asText()) && chat.path("response").asText().startsWith("[sandbox] java sdk"), "chat through the sandbox provider", chat.path("response").asText());

    try {
      c.call("listAlerts", CallArgs.none());
      report(true, "generic operation: call(listAlerts) with the operator key", "ok");
    } catch (QodiqaException e) {
      report(false, "generic operation: call(listAlerts) with the operator key", e.getMessage());
    }

    QodiqaClient bad = QodiqaClient.builder().baseUrl(base).signToken("sk_" + "0".repeat(64)).maxRetries(0).build();
    try {
      bad.call("signRequest", new CallArgs(null, null, null, JsonNodeFactory.instance.objectNode().set("request", JsonNodeFactory.instance.objectNode().put("method", "POST").put("path", "/ai/chat"))));
      report(false, "error mapping: a wrong signing key is an authentication error", "no exception");
    } catch (QodiqaException e) {
      report(e.kind() == QodiqaException.Kind.AUTHENTICATION, "error mapping: a wrong signing key is an authentication error", String.valueOf(e.kind()));
    }
    System.exit(failed ? 1 : 0);
  }
}
