package dev.qodiqa.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Verification of transparency inclusion proofs (proof version 2): entry hash, Merkle path, shape of the path for (leafIndex, treeSize), and the entry and root signatures. */
public final class Transparency {
  private Transparency() {}

  /** Each check's outcome. */
  public static final class Detail {
    public boolean entryHashValid, merklePathValid, entrySignatureValid, rootSignatureValid, leafIndexValid, keyValid;
    public String keyStatus;

    public boolean allPassed() {
      return entryHashValid && merklePathValid && leafIndexValid && keyValid && entrySignatureValid && rootSignatureValid;
    }
  }

  private static final List<String> ENTRY_FIELDS = List.of("transparencyId", "entryType", "artifactId", "evidenceChainId", "verificationId", "payloadHash", "previousEntryHash", "signerKeyId");
  private static final List<String> ROOT_FIELDS = List.of("rootId", "seqFrom", "seqTo", "entryCount", "rootHash", "previousRootHash");

  private static ObjectNode pick(JsonNode rec, List<String> fields) {
    ObjectNode o = JsonNodeFactory.instance.objectNode();
    for (String f : fields) o.set(f, rec.has(f) ? rec.get(f) : JsonNodeFactory.instance.nullNode());
    return o;
  }

  static String entryHash(JsonNode entry) {
    return Verify.domainHashHex(Verify.DOMAIN_TRANSPARENCY_ENTRY, Canonical.canonicalize(pick(entry, ENTRY_FIELDS)));
  }

  static byte[] rootSigningBuffer(JsonNode root) {
    return Verify.domainHash(Verify.DOMAIN_TRANSPARENCY_ROOT, Canonical.canonicalize(pick(root, ROOT_FIELDS)));
  }

  /** The sides a path for (leafIndex, treeSize) must have, leaf first; null for an impossible index. */
  public static List<String> expectedPathSides(long leafIndex, long treeSize) {
    if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return null;
    List<String> sides = new ArrayList<>();
    long size = treeSize, idx = leafIndex;
    while (size > 1) {
      long k = 1;
      while (k * 2 < size) k *= 2;
      if (idx < k) {
        sides.add("right");
        size = k;
      } else {
        sides.add("left");
        idx -= k;
        size -= k;
      }
    }
    Collections.reverse(sides);
    return sides;
  }

  private static byte[] sha(byte[]... parts) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    for (byte[] p : parts) md.update(p);
    return md.digest();
  }

  public static boolean verifyInclusionPath(String entryHashHex, JsonNode path, String rootHex, long leafIndex, long treeSize) {
    try {
      if (entryHashHex == null || entryHashHex.isEmpty() || rootHex == null || rootHex.isEmpty() || path == null || !path.isArray()) return false;
      List<String> sides = expectedPathSides(leafIndex, treeSize);
      if (sides == null || path.size() != sides.size()) return false;
      for (int i = 0; i < sides.size(); i++) {
        JsonNode step = path.get(i);
        if (!step.isObject() || !step.path("side").isTextual() || !step.path("side").textValue().equals(sides.get(i))) return false;
      }
      byte[] leaf = Verify.unhex(entryHashHex);
      if (leaf == null) return false;
      byte[] cur = sha(new byte[] {0x00}, leaf);
      for (JsonNode step : path) {
        if (!step.path("hash").isTextual()) return false;
        byte[] sib = Verify.unhex(step.get("hash").textValue());
        if (sib == null) return false;
        cur = "right".equals(step.get("side").textValue()) ? sha(new byte[] {0x01}, cur, sib) : sha(new byte[] {0x01}, sib, cur);
      }
      return Arrays.equals(cur, Verify.unhex(rootHex));
    } catch (Exception e) {
      return false;
    }
  }

  /** Number(x) followed by Number.isInteger, as the JavaScript verifier does; Long.MIN_VALUE when it is not. */
  private static long jsInt(JsonNode n) {
    double d;
    if (n == null) return Long.MIN_VALUE;
    if (n.isNumber()) d = n.decimalValue().doubleValue();
    else if (n.isTextual()) {
      try {
        d = Double.parseDouble(n.textValue().trim());
      } catch (NumberFormatException e) {
        return Long.MIN_VALUE;
      }
    } else return Long.MIN_VALUE;
    if (d != Math.floor(d) || Math.abs(d) > Verify.MAX_SAFE_INTEGER) return Long.MIN_VALUE;
    return (long) d;
  }

  public static Detail verifyProof(JsonNode proof, Verify.KeyProvider keys) {
    Detail d = new Detail();
    try {
      if (proof == null || !proof.isObject() || !proof.path("entry").isObject() || !proof.path("root").isObject() || !proof.path("proof").isObject()) return d;
      if (!"2".equals(proof.path("proofVersion").asText(null)) || !"TRANSPARENCY_INCLUSION".equals(proof.path("proofType").asText(null))) return d;
      JsonNode entry = proof.get("entry"), root = proof.get("root"), pd = proof.get("proof");
      String entryHashStored = entry.path("entryHash").asText(null);
      d.entryHashValid = entryHash(entry).equals(entryHashStored);
      long leaf = jsInt(pd.get("leafIndex")), size = jsInt(pd.get("treeSize"));
      d.leafIndexValid = leaf != Long.MIN_VALUE && size != Long.MIN_VALUE && leaf >= 0 && leaf < size;
      long count = jsInt(root.get("entryCount"));
      boolean pathValid = count != Long.MIN_VALUE && count == size && d.leafIndexValid && verifyInclusionPath(entryHashStored, pd.get("merklePath"), root.path("rootHash").asText(null), leaf, size);
      boolean rootAgrees = pd.path("merkleRoot").isTextual() && pd.get("merkleRoot").textValue().equals(root.path("rootHash").asText(null));
      d.merklePathValid = pathValid && rootAgrees;
      Verify.ResolvedKey k = safe(keys, entry.path("signerKeyId").asText(null));
      if (k != null) {
        d.keyValid = "active".equals(k.status()) || "deprecated".equals(k.status());
        d.keyStatus = k.status();
        if (d.keyValid) d.entrySignatureValid = Verify.verifyEd25519(Verify.unhex(entryHash(entry)), entry.path("signature").asText(null), k.pubDer());
      }
      Verify.ResolvedKey rk = safe(keys, root.path("signerKeyId").asText(null));
      if (rk != null && ("active".equals(rk.status()) || "deprecated".equals(rk.status()))) {
        d.rootSignatureValid = Verify.verifyEd25519(rootSigningBuffer(root), root.path("signature").asText(null), rk.pubDer());
      }
    } catch (RuntimeException e) {
      // every check that could not be made stays false
    }
    return d;
  }

  private static Verify.ResolvedKey safe(Verify.KeyProvider keys, String id) {
    try {
      return id == null ? null : keys.publicKey(id);
    } catch (Exception e) {
      return null;
    }
  }
}
