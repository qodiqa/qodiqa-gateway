package dev.qodiqa.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import dev.qodiqa.sdk.QodiqaClient.CallArgs;
import dev.qodiqa.sdk.QodiqaClient.Operation;
import dev.qodiqa.sdk.QodiqaException.Kind;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClientTest {
  record Seen(String method, String uri, String auth, String body, String otp) {}

  HttpServer server;
  final List<Seen> seen = new CopyOnWriteArrayList<>();
  volatile HttpHandler handler;

  String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    handler = ClientTest::ok;
    server.createContext("/", x -> {
      byte[] b = x.getRequestBody().readAllBytes();
      seen.add(new Seen(x.getRequestMethod(), x.getRequestURI().getRawPath() + (x.getRequestURI().getRawQuery() == null ? "" : "?" + x.getRequestURI().getRawQuery()),
          x.getRequestHeaders().getFirst("Authorization"), new String(b, StandardCharsets.UTF_8), x.getRequestHeaders().getFirst("X-QODIQA-OTP")));
      handler.handle(x);
    });
    server.start();
  }

  @AfterEach
  void stop() { server.stop(0); }

  static void reply(HttpExchange x, int status, String type, byte[] body, String... headers) throws IOException {
    x.getResponseHeaders().set("Content-Type", type);
    for (int i = 0; i + 1 < headers.length; i += 2) x.getResponseHeaders().set(headers[i], headers[i + 1]);
    x.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
    if (body.length > 0) x.getResponseBody().write(body);
    x.close();
  }

  static void ok(HttpExchange x) throws IOException {
    if (x.getRequestURI().getPath().endsWith("/pdf")) reply(x, 200, "application/pdf", new byte[] {0x25, 0x50, 0x44, 0x46, (byte) 0xff, (byte) 0xfe});
    else reply(x, 200, "application/json", "{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
  }

  static void json(HttpExchange x, int status, String body, String... headers) throws IOException {
    reply(x, status, "application/json", body.getBytes(StandardCharsets.UTF_8), headers);
  }

  QodiqaClient client() {
    return QodiqaClient.builder().baseUrl(url()).apiKey("ok_" + "a".repeat(64)).signToken("sk_" + "b".repeat(64)).maxRetries(1).build();
  }

  @Test
  void operationTableCoversTheContract() throws Exception {
    java.nio.file.Path spec = java.nio.file.Path.of("..", "..", "docs", "api", "openapi.json");
    org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.exists(spec), "repository checkout required");
    JsonNode doc = Canonical.MAPPER.readTree(java.nio.file.Files.readString(spec));
    List<String> contract = new ArrayList<>();
    doc.get("paths").fields().forEachRemaining(p -> {
      for (String m : new String[] {"get", "post", "put", "patch", "delete"}) if (p.getValue().has(m)) contract.add(p.getValue().get(m).get("operationId").asText() + " " + m.toUpperCase() + " " + p.getKey());
    });
    List<String> sdk = new ArrayList<>();
    for (Operation o : QodiqaClient.operations()) sdk.add(o.id() + " " + o.method() + " " + o.path());
    java.util.Collections.sort(contract);
    java.util.Collections.sort(sdk);
    assertTrue(contract.size() > 300);
    assertEquals(contract, sdk);
  }

  @Test
  void everyNonStreamingOperationIsCalledCorrectly() {
    QodiqaClient c = client();
    int n = 0;
    for (Operation op : QodiqaClient.operations()) {
      if (op.response().equals("sse") || op.body().equals("form") || op.body().equals("raw")) continue;
      Map<String, String> path = new java.util.HashMap<>();
      for (String p : op.pathParams()) path.put(p, "v/" + p + " 1");
      Map<String, String> query = new java.util.HashMap<>();
      for (String q : op.requiredQuery()) query.put(q, "x");
      JsonNode body = op.body().equals("json") ? Canonical.parse("{\"probe\":true}") : null;
      seen.clear();
      var r = c.call(op.id(), new CallArgs(path, query, null, body));
      assertEquals(200, r.status(), op.id());
      assertEquals(1, seen.size(), op.id());
      Seen s = seen.get(0);
      String want = op.path();
      for (String p : op.pathParams()) want = want.replace("{" + p + "}", QodiqaClient.pathEscape("v/" + p + " 1"));
      assertEquals(op.method(), s.method(), op.id());
      assertEquals(want, s.uri().split("\\?", 2)[0], op.id());
      switch (op.auth()) {
        case "none" -> assertEquals(null, s.auth(), op.id());
        case "sign" -> assertEquals("Bearer sk_" + "b".repeat(64), s.auth(), op.id());
        default -> assertEquals("Bearer ok_" + "a".repeat(64), s.auth(), op.id());
      }
      if (op.response().equals("binary")) assertEquals(6, r.raw().length, op.id());
      n++;
    }
    assertTrue(n >= 350, "only " + n);
  }

  @Test
  void argumentMistakesFailBeforeAnyRequest() {
    QodiqaClient c = client();
    Operation one = QodiqaClient.operations().stream().filter(o -> o.pathParams().size() == 1 && o.method().equals("GET")).findFirst().orElseThrow();
    Operation noBody = QodiqaClient.operations().stream().filter(o -> o.body().equals("none") && o.pathParams().isEmpty() && o.method().equals("GET") && o.auth().equals("ops")).findFirst().orElseThrow();
    Operation needs = QodiqaClient.operations().stream().filter(o -> o.bodyRequired() && o.pathParams().isEmpty() && o.auth().equals("ops")).findFirst().orElseThrow();
    String p = one.pathParams().get(0);
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(one.id(), CallArgs.none())).getMessage().contains("required"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(one.id(), new CallArgs(Map.of(p, ""), null, null, null))).getMessage().contains("required"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(one.id(), new CallArgs(Map.of(p, "x", "extra", "y"), null, null, null))).getMessage().contains("unknown path parameter"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(one.id(), new CallArgs(Map.of(p, "x"), Map.of("nope", "1"), null, null))).getMessage().contains("unknown query parameter"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(noBody.id(), new CallArgs(null, null, null, Canonical.parse("{}")))).getMessage().contains("no request body"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(noBody.id(), new CallArgs(null, null, Map.of("X-Nope", "1"), null))).getMessage().contains("unknown header"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call(needs.id(), CallArgs.none())).getMessage().contains("body is required"));
    assertTrue(assertThrows(QodiqaException.class, () -> c.call("noSuchOperation", CallArgs.none())).getMessage().contains("unknown operation"));
    assertEquals(0, seen.size());
    QodiqaClient noKey = QodiqaClient.builder().baseUrl(url()).build();
    assertEquals(Kind.AUTHENTICATION, assertThrows(QodiqaException.class, () -> noKey.call(noBody.id(), CallArgs.none())).kind());
    assertThrows(QodiqaException.class, () -> QodiqaClient.builder().baseUrl("ftp://x").build());
    assertThrows(QodiqaException.class, () -> QodiqaClient.builder().baseUrl("https://u:p@host").build());
  }

  Operation anyPublicGet() {
    return QodiqaClient.operations().stream().filter(o -> o.auth().equals("none") && o.pathParams().isEmpty() && o.method().equals("GET") && o.response().equals("json") && o.requiredQuery().isEmpty()).findFirst().orElseThrow();
  }

  @Test
  void errorShapesAndRetryPolicy() {
    AtomicInteger hits = new AtomicInteger();
    handler = x -> {
      hits.incrementAndGet();
      String path = x.getRequestURI().getPath();
      if (path.equals("/rate")) json(x, 429, "{\"error\":\"RATE_LIMITED\",\"reason\":\"BURST\",\"surface\":\"sign\",\"retryAfterSeconds\":1}", "Retry-After", "0");
      else if (path.equals("/mgmt")) json(x, 404, "{\"status\":\"error\",\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"no such thing\",\"details\":{\"id\":\"x\"}},\"requestId\":\"req-1\"}");
      else if (path.equals("/block")) json(x, 403, "{\"decision\":\"BLOCK\",\"reason\":\"KEY_REVOKED\",\"details\":{\"message\":\"revoked\"},\"requestId\":\"req-2\"}");
      else json(x, 503, "{\"error\":{\"code\":\"SERVER_OVERLOADED\",\"message\":\"busy\"}}");
    };
    QodiqaClient.Response r429 = new QodiqaClient.Response(429, Map.of("Retry-After", List.of("2")), "application/json", "{\"error\":\"RATE_LIMITED\",\"reason\":\"BURST\",\"surface\":\"sign\"}".getBytes(StandardCharsets.UTF_8));
    QodiqaException e = QodiqaClient.fromResponse(r429);
    assertEquals(Kind.RATE_LIMIT, e.kind());
    assertEquals("RATE_LIMITED", e.reason());
    assertEquals("BURST", e.details().get("blockedBy"));
    assertEquals(2, e.retryAfterSeconds());
    e = QodiqaClient.fromResponse(new QodiqaClient.Response(404, Map.of(), "application/json", "{\"status\":\"error\",\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"no such thing\",\"details\":{\"id\":\"x\"}},\"requestId\":\"req-1\"}".getBytes(StandardCharsets.UTF_8)));
    assertEquals(Kind.NOT_FOUND, e.kind());
    assertTrue(e.getMessage().contains("no such thing") && e.getMessage().contains("req-1"));
    e = QodiqaClient.fromResponse(new QodiqaClient.Response(403, Map.of(), "application/json", "{\"decision\":\"BLOCK\",\"reason\":\"KEY_REVOKED\",\"details\":{\"message\":\"revoked\"},\"requestId\":\"req-2\"}".getBytes(StandardCharsets.UTF_8)));
    assertEquals(Kind.VERIFICATION, e.kind());
    assertEquals("revoked", e.getMessage().split(" \\(")[0]);
    // SERVER_OVERLOADED on a GET is retried (maxRetries 1 => 2 attempts) and then surfaced
    QodiqaClient c = QodiqaClient.builder().baseUrl(url()).maxRetries(1).build();
    QodiqaException thrown = assertThrows(QodiqaException.class, () -> c.call(anyPublicGet().id(), CallArgs.none()));
    assertEquals("SERVER_OVERLOADED", thrown.reason());
    assertEquals(2, hits.get());
  }

  @Test
  void mfaStepUpIsResentOnce() {
    AtomicInteger hits = new AtomicInteger();
    handler = x -> {
      hits.incrementAndGet();
      if ("123456".equals(x.getRequestHeaders().getFirst("X-QODIQA-OTP"))) ok(x);
      else json(x, 401, "{\"error\":{\"code\":\"MFA_REQUIRED\",\"message\":\"code needed\"}}");
    };
    Operation op = QodiqaClient.operations().stream().filter(o -> o.auth().equals("ops") && o.pathParams().isEmpty() && o.method().equals("GET") && o.body().equals("none") && o.requiredQuery().isEmpty() && o.response().equals("json")).findFirst().orElseThrow();
    QodiqaClient c = QodiqaClient.builder().baseUrl(url()).apiKey("ok_x").maxRetries(2).otpSupplier(() -> "123456").build();
    assertEquals(200, c.call(op.id(), CallArgs.none()).status());
    assertEquals(2, hits.get());
    hits.set(0);
    QodiqaException e = assertThrows(QodiqaException.class, () -> QodiqaClient.builder().baseUrl(url()).apiKey("ok_x").build().call(op.id(), CallArgs.none()));
    assertEquals(Kind.MFA_REQUIRED, e.kind());
    assertEquals(1, hits.get());
  }

  @Test
  void timeoutAndNetworkErrors() {
    handler = x -> {
      try {
        Thread.sleep(700);
      } catch (InterruptedException ignored) {
        // test server
      }
      ok(x);
    };
    QodiqaClient c = QodiqaClient.builder().baseUrl(url()).timeout(Duration.ofMillis(200)).maxRetries(0).build();
    assertEquals(Kind.TIMEOUT, assertThrows(QodiqaException.class, () -> c.call(anyPublicGet().id(), CallArgs.none())).kind());
    QodiqaClient dead = QodiqaClient.builder().baseUrl("http://127.0.0.1:1").timeout(Duration.ofSeconds(3)).maxRetries(0).build();
    assertEquals(Kind.NETWORK, assertThrows(QodiqaException.class, () -> dead.call(anyPublicGet().id(), CallArgs.none())).kind());
  }

  @Test
  void streamYieldsEventsUntilDone() throws Exception {
    handler = x -> {
      boolean cut = x.getRequestURI().getQuery() != null && x.getRequestURI().getQuery().contains("cut");
      String body = cut ? "data: {\"n\":1}\n\n" : ": keep-alive\n\ndata: {\"n\":1}\n\ndata: {\"n\":2,\ndata: \"m\":3}\n\ndata: [DONE]\n\n";
      reply(x, 200, "text/event-stream", body.getBytes(StandardCharsets.UTF_8));
    };
    Operation sse = QodiqaClient.operations().stream().filter(o -> o.response().equals("sse") && o.pathParams().isEmpty()).findFirst().orElseThrow();
    QodiqaClient c = client();
    List<String> got = new ArrayList<>();
    try (var s = c.stream(sse.id(), CallArgs.none())) {
      JsonNode ev;
      while ((ev = s.next()) != null) got.add(ev.toString());
    }
    assertEquals(List.of("{\"n\":1}", "{\"n\":2,\"m\":3}"), got);
    assertEquals(Kind.VALIDATION, assertThrows(QodiqaException.class, () -> c.call(sse.id(), CallArgs.none())).kind());
    assertNotNull(URLDecoder.decode("a%20b", StandardCharsets.UTF_8));
    InputStream unused = null;
    assertEquals(null, unused);
  }
}
