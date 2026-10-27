package dev.qodiqa.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import dev.qodiqa.sdk.Verify.ArtifactVerification;
import dev.qodiqa.sdk.Verify.ArtifactVerifier;
import dev.qodiqa.sdk.Verify.Limits;
import dev.qodiqa.sdk.Verify.StaticKeyProvider;
import dev.qodiqa.sdk.Verify.TimedKey;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Conformance against the shared, language-neutral vectors (copied byte-for-byte from docs/protocol/vectors and test-vectors by scripts/sdk/generate-operations.js; npm run sdk:check
 * fails when the copies differ). The same vectors pass in the JavaScript, Python and Go SDKs and in two independent verifiers; nothing is regenerated here.
 */
class ConformanceTest {
  static JsonNode load(String name) throws IOException {
    try (InputStream in = ConformanceTest.class.getResourceAsStream("/vectors/" + name)) {
      assertNotNull(in, name);
      return Canonical.MAPPER.readTree(in);
    }
  }

  @Test
  void canonicalizationValidVectors() throws IOException {
    JsonNode v = load("qodiqa-protocol-vectors.json").get("canonicalization").get("valid");
    assertTrue(v.size() >= 8);
    for (JsonNode c : v) assertEquals(c.get("canonical").asText(), Canonical.canonicalize(c.get("input")), c.get("name").asText());
  }

  @Test
  void canonicalizationRefusals() {
    for (String k : new String[] {"__proto__", "constructor", "prototype"}) {
      var o = JsonNodeFactory.instance.objectNode();
      o.put(k, 1);
      assertEquals("FORBIDDEN_KEY", assertThrows(Canonical.CanonicalizationException.class, () -> Canonical.canonicalize(o)).code());
    }
    var deep = (JsonNode) JsonNodeFactory.instance.numberNode(1);
    for (int i = 0; i < 1100; i++) {
      var o = JsonNodeFactory.instance.objectNode();
      o.set("a", deep);
      deep = o;
    }
    JsonNode d = deep;
    assertEquals("MAX_DEPTH_EXCEEDED", assertThrows(Canonical.CanonicalizationException.class, () -> Canonical.canonicalize(d)).code());
    assertEquals("NON_FINITE_NUMBER", assertThrows(Canonical.CanonicalizationException.class, () -> Canonical.canonicalize(Canonical.parse("{\"x\":1e999}"))).code());
  }

  @Test
  void numbersAreFormattedLikeEcmaScript() {
    Map<String, String> cases = Map.ofEntries(Map.entry("0", "0"), Map.entry("-0", "0"), Map.entry("1", "1"), Map.entry("-1", "-1"), Map.entry("1.5", "1.5"), Map.entry("0.1", "0.1"),
        Map.entry("100", "100"), Map.entry("1e21", "1e+21"), Map.entry("1e-7", "1e-7"), Map.entry("123456789012345680000", "123456789012345680000"), Map.entry("0.000001", "0.000001"),
        Map.entry("1.7976931348623157e308", "1.7976931348623157e+308"), Map.entry("5e-324", "5e-324"), Map.entry("9007199254740991", "9007199254740991"),
        Map.entry("0.30000000000000004", "0.30000000000000004"), Map.entry("1e20", "100000000000000000000"), Map.entry("-1.25e-10", "-1.25e-10"));
    cases.forEach((in, want) -> assertEquals(want, Canonical.canonicalize(Canonical.parse(in)), in));
  }

  @Test
  void keysAreOrderedByUtf16CodeUnitAndLoneSurrogatesAreEscaped() {
    // U+FF5E (a BMP character) sorts AFTER U+1F600 (a surrogate pair, 0xD83D...) by UTF-16 code units, but before it by code point
    assertEquals("{\"😀\":1,\"～\":2}", Canonical.canonicalize(Canonical.parse("{\"～\":2,\"😀\":1}")));
    var s = JsonNodeFactory.instance.textNode("a\uD800b");
    assertEquals("\"a\\ud800b\"", Canonical.canonicalize(s));
  }

  @Test
  void domainTagsArtifactsRequestBindingAndPolicyHash() throws Exception {
    JsonNode v = load("qodiqa-protocol-vectors.json");
    String sample = v.get("domainTags").get("sampleCanonical").asText();
    for (JsonNode t : v.get("domainTags").get("tags")) assertEquals(t.get("digestHex").asText(), Verify.domainHashHex(t.get("tag").asText(), sample), t.get("tag").asText());
    byte[] spki = Base64.getDecoder().decode(v.get("testKeys").get("signerPublicKeySpkiB64").asText());
    for (JsonNode a : v.get("artifacts")) {
      JsonNode art = a.get("artifact");
      byte[] h = Verify.envelopeHash(art);
      assertEquals(a.get("envelopeHashHex").asText(), Verify.hex(h), a.get("name").asText());
      assertTrue(Verify.verifyEd25519(h, art.get("signature").asText(), spki), a.get("name").asText());
    }
    for (JsonNode r : v.get("requestBinding").get("hashes")) {
      JsonNode q = r.get("request");
      assertEquals(r.get("requestHashHex").asText(), Verify.requestHash(q.get("method").asText(), q.get("path").asText(), q.get("body")), r.get("name").asText());
    }
    for (JsonNode c : v.get("policyHash").get("cases")) assertEquals(c.get("policyHashHex").asText(), Verify.policyHash(c.get("policies")), c.get("name").asText());
  }

  @Test
  void verificationDecisions() throws Exception {
    JsonNode ver = load("qodiqa-protocol-vectors.json").get("verification");
    Map<String, TimedKey> keys = new HashMap<>();
    for (JsonNode k : ver.get("keys")) {
      JsonNode t = k.get("timeline");
      keys.put(k.get("publicKeyId").asText(), new TimedKey(Base64.getDecoder().decode(k.get("publicKeySpkiB64").asText()),
          new Verify.KeyTimeline(t.get("status").asText(), t.path("activatedAt").asText(null), t.path("deprecatedAt").asText(null))));
    }
    JsonNode l = ver.get("limits");
    Limits lim = new Limits(l.get("futureSkewMs").asLong(), l.get("maxArtifactAgeMs").asLong(), l.get("deprecatedWindowMs").asLong());
    assertTrue(ver.get("cases").size() >= 21);
    for (JsonNode c : ver.get("cases")) {
      var d = Verify.decideArtifact(c.get("artifact"), keys, ver.get("nowMs").asLong(), lim);
      assertEquals(c.get("expected").get("decision").asText() + "/" + c.get("expected").get("reason").asText(), d.decision() + "/" + d.reason(), c.get("name").asText());
    }
  }

  @Test
  void artifactVectors() throws Exception {
    JsonNode f = load("artifact-v1.json");
    assertEquals(f.get("vectorCount").get("artifact").asInt(), f.get("artifactVectors").size());
    for (JsonNode v : f.get("artifactVectors")) {
      long at = v.get("verifyAt").asLong();
      ArtifactVerifier ver = new ArtifactVerifier(new StaticKeyProvider(v.get("keySet")), null, v.get("clockToleranceMs").asLong(), false, () -> at);
      ArtifactVerification r = ver.verify(v.get("artifact"), null);
      JsonNode e = v.get("expected");
      String id = v.get("id").asText();
      assertEquals(e.get("verificationStatus").asText(), r.verificationStatus, id);
      assertEquals(e.get("signatureValid").asBoolean(), r.signatureValid, id);
      assertEquals(e.get("payloadHashValid").asBoolean(), r.payloadHashValid, id);
      assertEquals(e.get("canonicalizationValid").asBoolean(), r.canonicalizationValid, id);
      assertEquals(e.get("keyValid").asBoolean(), r.keyValid, id);
      assertEquals(e.get("timestampValid").asBoolean(), r.timestampValid, id);
      assertEquals(e.get("expiryValid").asBoolean(), r.expiryValid, id);
      assertEquals(e.get("failedStage").isNull() ? null : e.get("failedStage").asText(), r.failedStage, id);
    }
  }

  @Test
  void transparencyVectors() throws Exception {
    JsonNode f = load("artifact-v1.json");
    assertEquals(f.get("vectorCount").get("transparency").asInt(), f.get("transparencyVectors").size());
    JsonNode first = f.get("artifactVectors").get(0);
    for (JsonNode v : f.get("transparencyVectors")) {
      String id = v.get("id").asText();
      JsonNode e = v.get("expected");
      StaticKeyProvider tk = new StaticKeyProvider(v.get("transparencyKeySet"));
      if (v.get("proof").isNull()) {
        long at = first.get("verifyAt").asLong();
        var r = new ArtifactVerifier(new StaticKeyProvider(first.get("keySet")), tk, 0, false, () -> at).verify(first.get("artifact"), null);
        assertEquals(e.get("transparencyVerified").asText(), r.transparencyVerified, id);
        continue;
      }
      var d = Transparency.verifyProof(v.get("proof"), tk);
      assertEquals(e.get("transparencyVerified").asText(), d.allPassed() ? "verified" : "failed", id);
      assertEquals(e.get("entryHashValid").asBoolean(), d.entryHashValid, id);
      assertEquals(e.get("merklePathValid").asBoolean(), d.merklePathValid, id);
      assertEquals(e.get("leafIndexValid").asBoolean(), d.leafIndexValid, id);
      assertEquals(e.get("keyValid").asBoolean(), d.keyValid, id);
      assertEquals(e.get("entrySignatureValid").asBoolean(), d.entrySignatureValid, id);
      assertEquals(e.get("rootSignatureValid").asBoolean(), d.rootSignatureValid, id);
    }
  }

  @Test
  void verifierWiringAndHostileInputNeverThrow() throws Exception {
    JsonNode f = load("artifact-v1.json");
    JsonNode first = f.get("artifactVectors").get(0), wrongRoot = f.get("transparencyVectors").get(1);
    long at = first.get("verifyAt").asLong();
    StaticKeyProvider kp = new StaticKeyProvider(first.get("keySet")), tk = new StaticKeyProvider(wrongRoot.get("transparencyKeySet"));
    var r = new ArtifactVerifier(kp, tk, 0, false, () -> at).verify(first.get("artifact"), wrongRoot.get("proof"));
    assertEquals("invalid", r.verificationStatus);
    assertEquals("TRANSPARENCY", r.failedStage);
    assertEquals("TRANSPARENCY", new ArtifactVerifier(kp, tk, 0, true, () -> at).verify(first.get("artifact"), null).failedStage);
    assertThrows(IllegalArgumentException.class, () -> new ArtifactVerifier(kp, null, 0, true, null));
    ArtifactVerifier v = new ArtifactVerifier(kp, tk, 0, false, () -> 1L);
    for (String in : new String[] {"null", "[]", "\"x\"", "{}", "{\"expiry\":1,\"payload\":[],\"publicKeyId\":\"k\",\"signature\":\"x\",\"timestamp\":0}",
        "{\"expiry\":1e400,\"payload\":{},\"publicKeyId\":\"k\",\"signature\":\"x\",\"timestamp\":1}",
        "{\"expiry\":2,\"payload\":{\"a\":{\"__proto__\":1}},\"publicKeyId\":\"k\",\"signature\":\"AAAA\",\"timestamp\":1}"}) {
      JsonNode n = Canonical.parse(in);
      assertFalse("valid".equals(v.verify(n, null).verificationStatus), in);
      Transparency.verifyProof(n, kp);
    }
  }
}
