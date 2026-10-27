package dev.qodiqa.sdk;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Protocol V1 canonical JSON: object keys sorted by UTF-16 code unit, no whitespace, strings escaped exactly like ECMAScript {@code JSON.stringify}, numbers formatted like
 * ECMAScript {@code Number.prototype.toString}. Pinned by the shared protocol vectors.
 */
public final class Canonical {
  private Canonical() {}

  static final int MAX_DEPTH = 1000;
  private static final Set<String> FORBIDDEN = Set.of("__proto__", "constructor", "prototype");

  /** The mapper every decoded value must come from: exact big decimals, no trailing tokens. */
  public static final ObjectMapper MAPPER =
      new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  /** Why a value has no canonical form. */
  public static final class CanonicalizationException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public CanonicalizationException(String code, String message) {
      super(code + ": " + message);
      this.code = code;
    }

    /** NON_FINITE_NUMBER, UNSUPPORTED_TYPE, MAX_DEPTH_EXCEEDED or FORBIDDEN_KEY. */
    public String code() {
      return code;
    }
  }

  public static JsonNode parse(String json) {
    try {
      return MAPPER.readTree(json);
    } catch (Exception e) {
      throw new IllegalArgumentException("invalid JSON: " + e.getMessage(), e);
    }
  }

  public static String canonicalize(JsonNode node) {
    StringBuilder sb = new StringBuilder();
    write(sb, node, 0);
    return sb.toString();
  }

  private static void write(StringBuilder sb, JsonNode n, int depth) {
    if (n == null || n.isNull() || n.isMissingNode()) {
      sb.append("null");
    } else if (n.isBoolean()) {
      sb.append(n.booleanValue() ? "true" : "false");
    } else if (n.isTextual()) {
      writeString(sb, n.textValue());
    } else if (n.isNumber()) {
      writeNumber(sb, n.decimalValue().doubleValue());
    } else if (n.isArray()) {
      if (depth > MAX_DEPTH) throw new CanonicalizationException("MAX_DEPTH_EXCEEDED", "nesting exceeds maximum depth of " + MAX_DEPTH);
      sb.append('[');
      boolean first = true;
      for (JsonNode item : n) {
        if (!first) sb.append(',');
        first = false;
        write(sb, item, depth + 1);
      }
      sb.append(']');
    } else if (n.isObject()) {
      if (depth > MAX_DEPTH) throw new CanonicalizationException("MAX_DEPTH_EXCEEDED", "nesting exceeds maximum depth of " + MAX_DEPTH);
      List<String> keys = new ArrayList<>();
      for (Iterator<Map.Entry<String, JsonNode>> it = n.fields(); it.hasNext(); ) {
        String k = it.next().getKey();
        if (FORBIDDEN.contains(k)) throw new CanonicalizationException("FORBIDDEN_KEY", "object key \"" + k + "\" is forbidden");
        keys.add(k);
      }
      keys.sort(String::compareTo); // String.compareTo compares UTF-16 code units, like JavaScript's default sort
      sb.append('{');
      boolean first = true;
      for (String k : keys) {
        if (!first) sb.append(',');
        first = false;
        writeString(sb, k);
        sb.append(':');
        write(sb, n.get(k), depth + 1);
      }
      sb.append('}');
    } else {
      throw new CanonicalizationException("UNSUPPORTED_TYPE", "cannot canonicalise a " + n.getNodeType() + " value");
    }
  }

  private static void writeString(StringBuilder sb, String s) {
    final String hex = "0123456789abcdef";
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\b' -> sb.append("\\b");
        case '\f' -> sb.append("\\f");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) {
            sb.append("\\u00").append(hex.charAt(c >> 4)).append(hex.charAt(c & 0xf));
          } else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
            sb.append(c).append(s.charAt(++i)); // a valid pair is written as is
          } else if (Character.isSurrogate(c)) {
            sb.append("\\u").append(String.format(Locale.ROOT, "%04x", (int) c)); // a lone surrogate is escaped, like a well-formed JSON.stringify
          } else {
            sb.append(c);
          }
        }
      }
    }
    sb.append('"');
  }

  private static void writeNumber(StringBuilder sb, double d) {
    if (Double.isNaN(d) || Double.isInfinite(d)) throw new CanonicalizationException("NON_FINITE_NUMBER", "NaN/Infinity is not a valid canonical number");
    sb.append(jsNumber(d));
  }

  /** ECMAScript Number::toString(10). Shortest round-trip digits are found by increasing the precision, so the result does not depend on the JDK's Double.toString. */
  static String jsNumber(double d) {
    if (d == 0) return "0";
    boolean neg = d < 0;
    double a = Math.abs(d);
    String digits = null;
    int exp = 0;
    for (int p = 0; p <= 16; p++) {
      String e = String.format(Locale.ROOT, "%." + p + "e", a); // d.ddde+XX
      if (Double.parseDouble(e) == a) {
        int ePos = e.indexOf('e');
        digits = e.substring(0, ePos).replace(".", "");
        exp = Integer.parseInt(e.substring(ePos + 1));
        break;
      }
    }
    if (digits == null) { // cannot happen for a finite double; keep a correct, if long, fallback
      BigDecimal bd = new BigDecimal(a);
      digits = bd.unscaledValue().toString();
      exp = digits.length() - 1 - bd.scale();
    }
    digits = digits.replaceAll("0+$", "");
    if (digits.isEmpty()) digits = "0";
    int k = digits.length();
    int n = exp + 1;
    String out;
    if (k <= n && n <= 21) {
      out = digits + "0".repeat(n - k);
    } else if (0 < n && n <= 21) {
      out = digits.substring(0, n) + "." + digits.substring(n);
    } else if (-6 < n && n <= 0) {
      out = "0." + "0".repeat(-n) + digits;
    } else {
      int x = n - 1;
      String sign = x < 0 ? "-" : "+";
      x = Math.abs(x);
      out = k == 1 ? digits + "e" + sign + x : digits.charAt(0) + "." + digits.substring(1) + "e" + sign + x;
    }
    return neg ? "-" + out : out;
  }
}
