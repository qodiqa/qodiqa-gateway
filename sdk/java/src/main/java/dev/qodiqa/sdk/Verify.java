package dev.qodiqa.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/** Offline verification of QODIQA artifacts (protocol V1): hashes, signatures, the artifact verifier, the gateway's decision procedure and request/policy hashes. */
public final class Verify {
  private Verify() {}

  public static final String DOMAIN_ARTIFACT = "QODIQA::ARTIFACT::V1";
  public static final String DOMAIN_TRANSPARENCY_ENTRY = "QODIQA::TRANSPARENCY::V1";
  public static final String DOMAIN_TRANSPARENCY_ROOT = "QODIQA::TRANSPARENCY_ROOT::V1";
  public static final String DOMAIN_REQUEST = "QODIQA::REQUEST::V1";
  public static final String DOMAIN_POLICY = "QODIQA::POLICY::V1";
  static final long MAX_SAFE_INTEGER = 9007199254740991L;

  /** SHA-256(utf8(tag) || utf8(canonical)): no separator byte. */
  public static byte[] domainHash(String tag, String canonical) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(tag.getBytes(StandardCharsets.UTF_8));
      md.update(canonical.getBytes(StandardCharsets.UTF_8));
      return md.digest();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static String domainHashHex(String tag, String canonical) {
    return hex(domainHash(tag, canonical));
  }

  public static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
    return sb.toString();
  }

  static byte[] unhex(String s) {
    if (s == null || s.length() % 2 != 0) return null;
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      int hi = Character.digit(s.charAt(2 * i), 16), lo = Character.digit(s.charAt(2 * i + 1), 16);
      if (hi < 0 || lo < 0) return null;
      out[i] = (byte) (hi * 16 + lo);
    }
    return out;
  }

  /** The hash an artifact signature covers. */
  public static byte[] envelopeHash(JsonNode artifact) {
    ObjectNode env = JsonNodeFactory.instance.objectNode();
    for (String f : new String[] {"expiry", "payload", "publicKeyId", "timestamp"}) env.set(f, artifact.get(f));
    return domainHash(DOMAIN_ARTIFACT, Canonical.canonicalize(env));
  }

  /** Ed25519 over a 32-byte hash with an SPKI DER key and a base64 signature; malformed input is simply "not valid". */
  public static boolean verifyEd25519(byte[] hash, String signatureB64, byte[] spkiDer) {
    try {
      if (hash == null || hash.length != 32 || spkiDer == null || spkiDer.length == 0 || signatureB64 == null) return false;
      byte[] sig = Base64.getDecoder().decode(signatureB64);
      if (sig.length != 64) return false;
      PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spkiDer));
      Signature s = Signature.getInstance("Ed25519");
      s.initVerify(pub);
      s.update(hash);
      return s.verify(sig);
    } catch (Exception e) {
      return false;
    }
  }

  /** A public key as a provider returns it. */
  public record ResolvedKey(byte[] pubDer, String status, String source) {}

  /** Resolves a key id; null means "unknown key". */
  public interface KeyProvider {
    ResolvedKey publicKey(String keyId) throws Exception;
  }

  /** A trust bundle held in memory: entries of {keyId, publicKey (base64 SPKI), status}. */
  public static final class StaticKeyProvider implements KeyProvider {
    private final Map<String, ResolvedKey> keys = new HashMap<>();

    public StaticKeyProvider(JsonNode entries) {
      for (JsonNode e : entries) {
        keys.put(e.get("keyId").asText(), new ResolvedKey(Base64.getDecoder().decode(e.get("publicKey").asText()), e.get("status").asText(), "live"));
      }
    }

    @Override
    public ResolvedKey publicKey(String keyId) {
      return keys.get(keyId);
    }
  }

  static boolean isNumber(JsonNode n) {
    return n != null && n.isNumber();
  }

  /** Like Number.isSafeInteger(x) && x > 0 for a JSON number read as a JavaScript double; -1 when it is not. */
  static long safePositiveInt(JsonNode n) {
    if (!isNumber(n)) return -1;
    double d = n.decimalValue().doubleValue();
    if (d != Math.floor(d) || d <= 0 || d > MAX_SAFE_INTEGER) return -1;
    return (long) d;
  }

  // ── ArtifactVerifier ─────────────────────────────────────────────────────

  /** The outcome of {@link ArtifactVerifier#verify}. */
  public static final class ArtifactVerification {
    public String verificationStatus = "invalid"; // valid | invalid | error
    public boolean signatureValid, payloadHashValid, canonicalizationValid, keyValid, expiryValid, timestampValid;
    public String keyId, keyStatus, keySource;
    public String transparencyVerified = "unavailable"; // verified | failed | unavailable
    public Transparency.Detail transparencyDetail;
    public final List<String> errors = new ArrayList<>();
    public final List<String> warnings = new ArrayList<>();
    public String failedStage; // null when valid
    public long verifiedAt;
  }

  private static final List<String> FIELDS = List.of("expiry", "payload", "publicKeyId", "signature", "timestamp");
  private static final Pattern BASE64 = Pattern.compile("^[A-Za-z0-9+/]+=*$");

  /** Verifies artifacts offline against a trust bundle. */
  public static final class ArtifactVerifier {
    private final KeyProvider keys;
    private final KeyProvider transparencyKeys;
    private final long clockToleranceMs;
    private final boolean requireTransparency;
    private final LongSupplier now;

    public ArtifactVerifier(KeyProvider keys, KeyProvider transparencyKeys, long clockToleranceMs, boolean requireTransparency, LongSupplier now) {
      if (keys == null) throw new IllegalArgumentException("ArtifactVerifier requires a keys provider");
      if (requireTransparency && transparencyKeys == null) throw new IllegalArgumentException("requireTransparency needs transparencyKeys");
      this.keys = keys;
      this.transparencyKeys = transparencyKeys;
      this.clockToleranceMs = clockToleranceMs;
      this.requireTransparency = requireTransparency;
      this.now = now == null ? System::currentTimeMillis : now;
    }

    public ArtifactVerification verify(JsonNode artifact, JsonNode transparencyProof) {
      long t0 = now.getAsLong();
      ArtifactVerification r = new ArtifactVerification();
      r.verifiedAt = t0;
      if (artifact == null || !artifact.isObject()) return fail(r, "STRUCTURE", "Artifact must be a plain object.");
      for (var it = artifact.fieldNames(); it.hasNext(); ) {
        String k = it.next();
        if (!FIELDS.contains(k)) return fail(r, "STRUCTURE", "Unexpected field \"" + k + "\" is not part of the artifact envelope.");
      }
      for (String f : FIELDS) if (!artifact.has(f)) return fail(r, "STRUCTURE", "Missing required field \"" + f + "\".");
      if (!artifact.get("payload").isObject()) return fail(r, "STRUCTURE", "Artifact payload must be a plain object.");
      long ts = safePositiveInt(artifact.get("timestamp"));
      if (ts < 0) return fail(r, "STRUCTURE", "Artifact timestamp must be a positive safe integer (Unix ms).");
      long exp = safePositiveInt(artifact.get("expiry"));
      if (exp < 0) return fail(r, "STRUCTURE", "Artifact expiry must be a positive safe integer (Unix ms).");
      if (ts >= exp) return fail(r, "STRUCTURE", "Artifact expiry must be greater than its timestamp.");
      JsonNode sigNode = artifact.get("signature");
      String sig = sigNode.isTextual() ? sigNode.textValue() : null;
      if (sig == null || !BASE64.matcher(sig).matches() || decodedLength(sig) != 64) return fail(r, "STRUCTURE", "Artifact signature must be base64 decoding to exactly 64 bytes.");
      JsonNode kn = artifact.get("publicKeyId");
      if (!kn.isTextual() || kn.textValue().isBlank()) return fail(r, "STRUCTURE", "Artifact publicKeyId must be a non-empty string.");
      String keyId = kn.textValue();
      byte[] hash;
      try {
        hash = envelopeHash(artifact);
        r.canonicalizationValid = true;
        r.payloadHashValid = true;
      } catch (RuntimeException e) {
        return fail(r, "CANONICALIZATION", "Envelope canonicalization failed: " + e.getMessage());
      }
      r.keyId = keyId;
      ResolvedKey key;
      try {
        key = keys.publicKey(keyId);
      } catch (Exception e) {
        r.verificationStatus = "error";
        return fail(r, "KEY_RESOLUTION", "Key provider failed to resolve \"" + keyId + "\": " + e.getMessage());
      }
      if (key == null) return fail(r, "KEY_RESOLUTION", "Unknown key id \"" + keyId + "\".");
      r.keyStatus = key.status();
      r.keySource = key.source() == null ? "live" : key.source();
      r.keyValid = "active".equals(key.status()) || "deprecated".equals(key.status());
      if (!r.keyValid) return fail(r, "KEY_RESOLUTION", "Key \"" + keyId + "\" has status \"" + key.status() + "\" and cannot verify.");
      r.timestampValid = ts <= t0 + clockToleranceMs;
      if (!r.timestampValid) return fail(r, "FUTURE_TIMESTAMP", "Artifact timestamp is in the future.");
      r.expiryValid = t0 - clockToleranceMs < exp;
      if (!r.expiryValid) return fail(r, "EXPIRED", "Artifact has expired.");
      r.signatureValid = verifyEd25519(hash, sig, key.pubDer());
      if (!r.signatureValid) return fail(r, "INVALID_SIGNATURE", "Ed25519 signature verification failed.");
      if (transparencyProof != null && !transparencyProof.isNull()) {
        if (transparencyKeys == null) {
          r.warnings.add("A transparencyProof was supplied but no transparencyKeys provider is configured; skipping transparency verification.");
        } else {
          r.transparencyDetail = Transparency.verifyProof(transparencyProof, transparencyKeys);
          r.transparencyVerified = r.transparencyDetail.allPassed() ? "verified" : "failed";
          if ("failed".equals(r.transparencyVerified)) return fail(r, "TRANSPARENCY", "Transparency inclusion proof verification failed.");
        }
      } else if (requireTransparency) {
        return fail(r, "TRANSPARENCY", "Transparency verification is required but no transparencyProof was supplied.");
      }
      r.verificationStatus = "valid";
      return r;
    }

    private static int decodedLength(String b64) {
      try {
        return Base64.getDecoder().decode(b64).length;
      } catch (IllegalArgumentException e) {
        return -1;
      }
    }

    private static ArtifactVerification fail(ArtifactVerification r, String stage, String msg) {
      r.failedStage = stage;
      r.errors.add(msg);
      return r;
    }
  }

  // ── The gateway's V1 decision procedure ──────────────────────────────────

  /** Protocol time limits in milliseconds. */
  public record Limits(long futureSkewMs, long maxArtifactAgeMs, long deprecatedWindowMs) {
    public static final Limits DEFAULT = new Limits(5000, 60000, 65000);
  }

  /** Lifecycle of one signing key (RFC 3339 instants, null when unknown). */
  public record KeyTimeline(String status, String activatedAt, String deprecatedAt) {}

  public record TimedKey(byte[] pubDer, KeyTimeline timeline) {}

  /** EXECUTE (all checks passed) or BLOCK with a reason. */
  public record Decision(String decision, String reason) {}

  private static final Pattern SIG86 = Pattern.compile("^[A-Za-z0-9+/]{86}==$");

  private static Long parseMs(String s) {
    if (s == null || s.isEmpty()) return null;
    try {
      return java.time.Instant.parse(s).toEpochMilli();
    } catch (Exception e) {
      return null;
    }
  }

  public static Decision decideArtifact(JsonNode a, Map<String, TimedKey> keys, long nowMs, Limits lim) {
    if (a == null || !a.isObject()) return block("INVALID_ARTIFACT");
    for (var it = a.fieldNames(); it.hasNext(); ) if (!FIELDS.contains(it.next())) return block("INVALID_ARTIFACT");
    for (String f : FIELDS) if (!a.has(f)) return block("INVALID_ARTIFACT");
    if (!a.get("payload").isObject()) return block("INVALID_ARTIFACT");
    long ts = safePositiveInt(a.get("timestamp")), exp = safePositiveInt(a.get("expiry"));
    if (ts < 0 || exp < 0) return block("INVALID_ARTIFACT");
    if (!a.get("signature").isTextual()) return block("INVALID_ARTIFACT");
    String sig = a.get("signature").textValue();
    byte[] raw;
    try {
      raw = Base64.getDecoder().decode(sig);
    } catch (IllegalArgumentException e) {
      return block("INVALID_SIGNATURE");
    }
    if (!SIG86.matcher(sig).matches() || !Base64.getEncoder().encodeToString(raw).equals(sig)) return block("INVALID_SIGNATURE");
    if (!a.get("publicKeyId").isTextual() || a.get("publicKeyId").textValue().isBlank()) return block("INVALID_ARTIFACT");
    TimedKey key = keys.get(a.get("publicKeyId").textValue());
    byte[] hash;
    try {
      hash = envelopeHash(a);
    } catch (RuntimeException e) {
      return block("INVALID_ARTIFACT");
    }
    if (key == null || !verifyEd25519(hash, sig, key.pubDer())) return block("INVALID_SIGNATURE");
    if (ts >= exp) return block("INVALID_ARTIFACT");
    if (ts > nowMs + lim.futureSkewMs()) return block("FUTURE_TIMESTAMP");
    if (nowMs >= exp) return block("EXPIRED");
    if (nowMs - ts > lim.maxArtifactAgeMs()) return block("TIME_SKEW_EXCEEDED");
    KeyTimeline t = key.timeline();
    switch (t.status() == null ? "" : t.status()) {
      case "revoked":
        return block("KEY_REVOKED");
      case "archived":
        return block("KEY_ARCHIVED");
      case "deprecated": {
        Long dep = parseMs(t.deprecatedAt());
        if (dep == null || ts >= dep || nowMs >= dep + lim.deprecatedWindowMs()) return block("KEY_DEPRECATED");
        return new Decision("EXECUTE", "ALL_CHECKS_PASSED");
      }
      case "active": {
        Long act = parseMs(t.activatedAt());
        if (act != null && ts < act - lim.futureSkewMs()) return block("KEY_NOT_YET_ACTIVE");
        return new Decision("EXECUTE", "ALL_CHECKS_PASSED");
      }
      default:
        return block("KEY_STATUS_UNKNOWN");
    }
  }

  private static Decision block(String reason) {
    return new Decision("BLOCK", reason);
  }

  /** hex(SHA-256("QODIQA::REQUEST::V1" || canonical({body, method: UPPER(method), path}))). */
  public static String requestHash(String method, String path, JsonNode body) {
    ObjectNode o = JsonNodeFactory.instance.objectNode();
    o.set("body", body == null ? JsonNodeFactory.instance.nullNode() : body);
    o.put("method", method.toUpperCase(java.util.Locale.ROOT));
    o.put("path", path);
    return domainHashHex(DOMAIN_REQUEST, Canonical.canonicalize(o));
  }

  /** hex(SHA-256("QODIQA::POLICY::V1" || canonical(policies with every "_"-prefixed key removed, recursively))). */
  public static String policyHash(JsonNode policies) {
    return domainHashHex(DOMAIN_POLICY, Canonical.canonicalize(stripUnderscore(policies)));
  }

  private static JsonNode stripUnderscore(JsonNode n) {
    if (n.isArray()) {
      var arr = JsonNodeFactory.instance.arrayNode();
      for (JsonNode x : n) arr.add(stripUnderscore(x));
      return arr;
    }
    if (n.isObject()) {
      ObjectNode o = JsonNodeFactory.instance.objectNode();
      for (var it = n.fields(); it.hasNext(); ) {
        var e = it.next();
        if (e.getKey().startsWith("_") && !e.getKey().equals("__proto__")) continue;
        o.set(e.getKey(), stripUnderscore(e.getValue()));
      }
      return o;
    }
    return n;
  }
}
