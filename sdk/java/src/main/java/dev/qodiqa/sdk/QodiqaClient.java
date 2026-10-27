package dev.qodiqa.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Client for a QODIQA gateway. {@link #call} performs any of the operations of the HTTP contract (see {@link #operations()}; generated from docs/api/openapi.json, drift-checked by
 * {@code npm run sdk:check} in the repository). Parameter mistakes are rejected before any request; credentials follow the contract; retries follow the gateway's contract
 * (idempotent verbs on 429/5xx, POST only on 429 and never on /ai/chat, SERVER_OVERLOADED always, never after MFA_LOCKED); an OTP supplier answers the operator MFA step-up once.
 */
public final class QodiqaClient {
  public static final String VERSION = "1.0.0";

  /** One documented operation. */
  public record Operation(String id, String method, String path, String auth, List<String> pathParams, List<String> query, List<String> requiredQuery, List<String> headers,
      String body, boolean bodyRequired, String response, String summary) {}

  private static final Map<String, Operation> OPERATIONS = loadOperations();

  private static Map<String, Operation> loadOperations() {
    try (InputStream in = QodiqaClient.class.getResourceAsStream("operations.json")) {
      if (in == null) throw new IllegalStateException("operations.json is missing from the SDK jar");
      JsonNode doc = Canonical.MAPPER.readTree(in);
      Map<String, Operation> out = new TreeMap<>();
      for (JsonNode o : doc.get("operations")) {
        out.put(o.get("id").asText(), new Operation(o.get("id").asText(), o.get("method").asText(), o.get("path").asText(), o.get("auth").asText(), strings(o.get("pathParams")),
            strings(o.get("query")), strings(o.get("requiredQuery")), strings(o.get("headers")), o.get("body").asText(), o.get("bodyRequired").asBoolean(), o.get("response").asText(),
            o.get("summary").asText()));
      }
      return java.util.Collections.unmodifiableMap(out);
    } catch (IOException e) {
      throw new IllegalStateException("operations.json cannot be read", e);
    }
  }

  private static List<String> strings(JsonNode a) {
    List<String> l = new ArrayList<>();
    for (JsonNode x : a) l.add(x.asText());
    return List.copyOf(l);
  }

  /** Every operation this SDK version can call, sorted by id. */
  public static List<Operation> operations() {
    return List.copyOf(OPERATIONS.values());
  }

  /** Builder for {@link QodiqaClient}. */
  public static final class Builder {
    private String baseUrl, apiKey, signToken;
    private Duration timeout = Duration.ofSeconds(30);
    private int maxRetries = 2;
    private Supplier<String> otpSupplier;
    private HttpClient http;

    public Builder baseUrl(String v) { this.baseUrl = v; return this; }
    /** Operator key (ok_...) for admin operations. */
    public Builder apiKey(String v) { this.apiKey = v; return this; }
    /** Signing key (sk_...) for POST /sign. */
    public Builder signToken(String v) { this.signToken = v; return this; }
    /** Bound for the whole call including retries. */
    public Builder timeout(Duration v) { this.timeout = v; return this; }
    /** Retries of a request that is safe to resend (0 = none). */
    public Builder maxRetries(int v) { this.maxRetries = v; return this; }
    /** Supplies the operator's MFA code when the gateway asks (MFA_REQUIRED); used once per call. */
    public Builder otpSupplier(Supplier<String> v) { this.otpSupplier = v; return this; }
    public Builder httpClient(HttpClient v) { this.http = v; return this; }

    public QodiqaClient build() {
      return new QodiqaClient(this);
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Arguments of a call. */
  public record CallArgs(Map<String, String> path, Map<String, String> query, Map<String, String> headers, JsonNode body) {
    public static CallArgs none() { return new CallArgs(null, null, null, null); }
    public static CallArgs of(Map<String, String> path, Map<String, String> query, JsonNode body) { return new CallArgs(path, query, null, body); }
  }

  /** The answer of a non-streaming call. */
  public record Response(int status, Map<String, List<String>> headers, String contentType, byte[] raw) {
    public String text() { return new String(raw, StandardCharsets.UTF_8); }
    public JsonNode json() { return Canonical.parse(text()); }
  }

  private final URI base;
  private final String apiKey, signToken;
  private final Duration timeout;
  private final int maxRetries;
  private final Supplier<String> otp;
  private final HttpClient http;

  private QodiqaClient(Builder b) {
    if (b.baseUrl == null || b.baseUrl.isBlank()) throw QodiqaException.validation("baseUrl is required");
    URI u;
    try {
      u = URI.create(b.baseUrl);
    } catch (IllegalArgumentException e) {
      throw QodiqaException.validation("baseUrl is not a URL");
    }
    if (u.getHost() == null || !(u.getScheme().equals("http") || u.getScheme().equals("https")) || u.getUserInfo() != null) throw QodiqaException.validation("baseUrl must be an http(s) URL without credentials");
    if (b.maxRetries < 0) throw QodiqaException.validation("maxRetries must not be negative");
    this.base = u;
    this.apiKey = b.apiKey;
    this.signToken = b.signToken;
    this.timeout = b.timeout;
    this.maxRetries = b.maxRetries;
    this.otp = b.otpSupplier;
    this.http = b.http != null ? b.http : HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build();
  }

  private static Operation op(String id) {
    Operation o = OPERATIONS.get(id);
    if (o == null) throw QodiqaException.validation("unknown operation \"" + id + "\"");
    return o;
  }

  private record Prepared(String path, Map<String, String> query, Map<String, String> headers, String body) {}

  private Prepared prepare(Operation op, CallArgs a) {
    Map<String, String> path = a.path() == null ? Map.of() : a.path();
    for (String k : path.keySet()) if (!op.pathParams().contains(k)) throw QodiqaException.validation(op.id() + ": unknown path parameter \"" + k + "\"");
    Matcher m = Pattern.compile("\\{([^}]+)}").matcher(op.path());
    StringBuilder sb = new StringBuilder();
    while (m.find()) {
      String v = path.get(m.group(1));
      if (v == null || v.isEmpty()) throw QodiqaException.validation(op.id() + ": path parameter \"" + m.group(1) + "\" is required");
      m.appendReplacement(sb, Matcher.quoteReplacement(pathEscape(v)));
    }
    m.appendTail(sb);
    Map<String, String> query = new LinkedHashMap<>();
    if (a.query() != null) {
      for (var e : a.query().entrySet()) {
        if (!op.query().contains(e.getKey())) throw QodiqaException.validation(op.id() + ": unknown query parameter \"" + e.getKey() + "\"");
        query.put(e.getKey(), e.getValue());
      }
    }
    for (String k : op.requiredQuery()) if (!query.containsKey(k)) throw QodiqaException.validation(op.id() + ": query parameter \"" + k + "\" is required");
    if (op.body().equals("none") && a.body() != null) throw QodiqaException.validation(op.id() + ": this operation takes no request body");
    if (op.bodyRequired() && a.body() == null) throw QodiqaException.validation(op.id() + ": a request body is required");
    if (op.body().equals("form") || op.body().equals("raw")) throw QodiqaException.validation(op.id() + ": " + op.body() + " request bodies are not supported by the generic client");
    Map<String, String> headers = new HashMap<>();
    if (a.headers() != null) {
      for (var e : a.headers().entrySet()) {
        if (op.headers().stream().noneMatch(h -> h.equalsIgnoreCase(e.getKey()))) throw QodiqaException.validation(op.id() + ": unknown header \"" + e.getKey() + "\"");
        headers.put(e.getKey(), e.getValue());
      }
    }
    switch (op.auth()) {
      case "ops" -> {
        if (apiKey == null || apiKey.isEmpty()) throw new QodiqaException(QodiqaException.Kind.AUTHENTICATION, 0, "UNAUTHENTICATED", "an operator API key (apiKey) is required for " + op.id(), null, null, 0, null);
        headers.put("Authorization", "Bearer " + apiKey);
      }
      case "sign" -> {
        if (signToken == null || signToken.isEmpty()) throw new QodiqaException(QodiqaException.Kind.AUTHENTICATION, 0, "UNAUTHENTICATED", "a signing key (signToken) is required for " + op.id(), null, null, 0, null);
        headers.put("Authorization", "Bearer " + signToken);
      }
      case "optional" -> {
        if (apiKey != null && !apiKey.isEmpty()) headers.put("Authorization", "Bearer " + apiKey);
      }
      default -> { }
    }
    return new Prepared(sb.toString(), query, headers, a.body() == null ? null : a.body().toString());
  }

  /** RFC 3986 path-segment escaping (a "/" inside a value is %2F). */
  static String pathEscape(String v) {
    return URLEncoder.encode(v, StandardCharsets.UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
  }

  private HttpRequest request(Operation op, Prepared p, Map<String, String> extraHeaders, Duration perRequest, boolean sse) {
    StringBuilder url = new StringBuilder(base.toString().replaceAll("/+$", "")).append(p.path());
    if (!p.query().isEmpty()) {
      url.append('?');
      boolean first = true;
      for (var e : p.query().entrySet()) {
        if (!first) url.append('&');
        first = false;
        url.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
      }
    }
    HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url.toString())).timeout(perRequest).header("User-Agent", "qodiqa-java/" + VERSION)
        .header("Accept", sse ? "text/event-stream" : "application/json, text/plain;q=0.5, */*;q=0.1");
    p.headers().forEach(rb::header);
    extraHeaders.forEach(rb::header);
    HttpRequest.BodyPublisher bp = p.body() == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(p.body());
    if (p.body() != null) rb.header("Content-Type", "application/json");
    return rb.method(op.method(), bp).build();
  }

  /** Performs a non-streaming operation by its operationId. */
  public Response call(String id, CallArgs args) {
    Operation op = op(id);
    if (op.response().equals("sse")) throw QodiqaException.validation(op.id() + " streams events: use stream()");
    Prepared p = prepare(op, args == null ? CallArgs.none() : args);
    long deadline = System.nanoTime() + timeout.toNanos();
    try {
      return send(op, p, Map.of(), deadline);
    } catch (QodiqaException e) {
      if (e.kind() == QodiqaException.Kind.MFA_REQUIRED && "MFA_REQUIRED".equals(e.reason()) && otp != null && p.headers().keySet().stream().noneMatch(h -> h.equalsIgnoreCase("X-QODIQA-OTP"))) {
        return send(op, p, Map.of("X-QODIQA-OTP", otp.get()), deadline);
      }
      throw e;
    }
  }

  private static final Pattern CHAT = Pattern.compile("(^|/)ai/chat(/stream)?/?$");

  private static boolean shouldRetry(QodiqaException e, String method, String path, boolean hasOtp) {
    if (hasOtp || "MFA_LOCKED".equals(e.reason())) return false;
    if ("SERVER_OVERLOADED".equals(e.reason())) return true;
    int s = e.status();
    if (method.equals("GET") || method.equals("PUT") || method.equals("DELETE") || method.equals("HEAD")) return s == 429 || s == 500 || s == 502 || s == 503 || s == 504;
    return s == 429 && !CHAT.matcher(path).find();
  }

  private Response send(Operation op, Prepared p, Map<String, String> extra, long deadline) {
    for (int attempt = 0; ; attempt++) {
      Duration left = Duration.ofNanos(deadline - System.nanoTime());
      if (left.isNegative() || left.isZero()) throw new QodiqaException(QodiqaException.Kind.TIMEOUT, 0, "TIMEOUT", op.id() + " timed out after " + timeout, null, null, 0, null);
      try {
        HttpResponse<byte[]> r = http.send(request(op, p, extra, left, false), HttpResponse.BodyHandlers.ofByteArray());
        String ct = r.headers().firstValue("Content-Type").orElse("");
        Response resp = new Response(r.statusCode(), r.headers().map(), ct, r.body());
        if (r.statusCode() >= 200 && r.statusCode() < 300) return resp;
        throw fromResponse(resp);
      } catch (QodiqaException e) {
        if (attempt >= maxRetries || !shouldRetry(e, op.method(), p.path(), extra.containsKey("X-QODIQA-OTP"))) throw e;
        long waitMs = e.retryAfterSeconds() > 0 ? e.retryAfterSeconds() * 1000L : backoffMs(attempt);
        if (System.nanoTime() + waitMs * 1_000_000L > deadline) throw e; // the wait would outlive the call: surface the real error
        sleep(waitMs);
      } catch (java.net.http.HttpTimeoutException e) {
        throw new QodiqaException(QodiqaException.Kind.TIMEOUT, 0, "TIMEOUT", op.id() + " timed out after " + timeout, null, null, 0, e);
      } catch (IOException e) {
        throw new QodiqaException(QodiqaException.Kind.NETWORK, 0, "NETWORK", "network error on " + op.method() + " " + op.path() + ": " + e.getMessage(), null, null, 0, e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new QodiqaException(QodiqaException.Kind.NETWORK, 0, "CANCELLED", op.id() + " was interrupted", null, null, 0, e);
      }
    }
  }

  private static long backoffMs(int attempt) {
    long d = Math.min(30_000L, 500L << attempt);
    return d / 2 + ThreadLocalRandom.current().nextLong(d / 2 + 1);
  }

  private static void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]+$");

  /** Reads every error shape of the gateway: decision envelope, management envelope {status:'error', error:{code,message,details}}, flat limiter body. */
  static QodiqaException fromResponse(Response r) {
    String reason = "UNKNOWN", message = "HTTP " + r.status();
    String requestId = null;
    Map<String, Object> details = new LinkedHashMap<>();
    if (r.contentType().contains("application/json")) {
      try {
        JsonNode b = r.json();
        if (b.isObject()) {
          if (b.path("reason").isTextual()) reason = b.get("reason").textValue();
          if (b.path("requestId").isTextual()) requestId = b.get("requestId").textValue();
          if (b.path("details").isObject()) {
            details.putAll(Canonical.MAPPER.convertValue(b.get("details"), Map.class));
            if (b.get("details").path("message").isTextual()) message = b.get("details").get("message").textValue();
          }
          if (b.path("message").isTextual()) message = b.get("message").textValue();
          JsonNode eo = b.path("error");
          if (eo.isObject()) {
            if (eo.path("code").isTextual()) reason = eo.get("code").textValue();
            if (eo.path("message").isTextual()) message = eo.get("message").textValue();
            if (eo.path("details").isObject()) details.putAll(Canonical.MAPPER.convertValue(eo.get("details"), Map.class));
          } else if (eo.isTextual() && CODE.matcher(eo.textValue()).matches()) {
            if (b.path("reason").isTextual()) details.put("blockedBy", b.get("reason").textValue());
            reason = eo.textValue();
            for (String k : new String[] {"surface", "dimension", "retryAfterSeconds"}) if (b.has(k) && !b.get(k).isNull()) details.put(k, Canonical.MAPPER.convertValue(b.get(k), Object.class));
          }
        }
      } catch (RuntimeException ignored) {
        // not JSON after all: keep the generic message
      }
    }
    int retryAfter = parseRetryAfter(first(r.headers(), "retry-after"));
    if (retryAfter > 0) details.put("retryAfter", retryAfter);
    if (requestId == null) requestId = first(r.headers(), "x-request-id");
    return new QodiqaException(QodiqaException.classify(r.status(), reason), r.status(), reason, message, requestId, details, retryAfter, null);
  }

  private static String first(Map<String, List<String>> h, String name) {
    for (var e : h.entrySet()) if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) return e.getValue().get(0);
    return null;
  }

  static int parseRetryAfter(String v) {
    if (v == null || v.isBlank()) return 0;
    try {
      return Math.max(0, Integer.parseInt(v.trim()));
    } catch (NumberFormatException ignored) {
      try {
        long secs = Duration.between(Instant.now(), ZonedDateTime.parse(v.trim(), DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()).toSeconds();
        return (int) Math.max(0, secs + 1);
      } catch (RuntimeException e) {
        return 0;
      }
    }
  }

  /** Events of an SSE operation until the terminal [DONE] frame; a stream that ends before it is an error. */
  public static final class EventStream implements AutoCloseable {
    private final BufferedReader in;
    private boolean done;

    EventStream(InputStream body) {
      this.in = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
    }

    /** The next event, or null after [DONE]. */
    public JsonNode next() {
      if (done) return null;
      try {
        List<String> data = new ArrayList<>();
        String line;
        while ((line = in.readLine()) != null) {
          if (line.isEmpty()) {
            if (data.isEmpty()) continue;
            String payload = String.join("\n", data);
            data.clear();
            if (payload.equals("[DONE]")) {
              done = true;
              return null;
            }
            try {
              return Canonical.parse(payload);
            } catch (IllegalArgumentException e) {
              throw new QodiqaException(QodiqaException.Kind.OTHER, 0, "INVALID_EVENT", "an event is not valid JSON", null, null, 0, e);
            }
          }
          if (line.startsWith(":")) continue;
          if (line.startsWith("data:")) data.add(line.substring(line.startsWith("data: ") ? 6 : 5));
        }
        throw new QodiqaException(QodiqaException.Kind.NETWORK, 0, "TRUNCATED_STREAM", "the stream ended before the terminal [DONE] frame", null, null, 0, null);
      } catch (IOException e) {
        throw new QodiqaException(QodiqaException.Kind.NETWORK, 0, "NETWORK", "reading the stream failed: " + e.getMessage(), null, null, 0, e);
      }
    }

    @Override
    public void close() {
      try {
        in.close();
      } catch (IOException ignored) {
        // already closed
      }
    }
  }

  /** Opens an SSE operation. There is no automatic retry (a partly consumed stream is not restartable). */
  public EventStream stream(String id, CallArgs args) {
    Operation op = op(id);
    if (!op.response().equals("sse")) throw QodiqaException.validation(op.id() + " does not stream events: use call()");
    Prepared p = prepare(op, args == null ? CallArgs.none() : args);
    try {
      HttpResponse<InputStream> r = http.send(request(op, p, Map.of(), Duration.ofHours(1), true), HttpResponse.BodyHandlers.ofInputStream());
      if (r.statusCode() < 200 || r.statusCode() >= 300) {
        byte[] raw = r.body().readNBytes(1 << 20);
        r.body().close();
        throw fromResponse(new Response(r.statusCode(), r.headers().map(), r.headers().firstValue("Content-Type").orElse(""), raw));
      }
      return new EventStream(r.body());
    } catch (IOException e) {
      throw new QodiqaException(QodiqaException.Kind.NETWORK, 0, "NETWORK", "network error on " + op.method() + " " + op.path() + ": " + e.getMessage(), null, null, 0, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new QodiqaException(QodiqaException.Kind.NETWORK, 0, "CANCELLED", op.id() + " was interrupted", null, null, 0, e);
    }
  }
}
