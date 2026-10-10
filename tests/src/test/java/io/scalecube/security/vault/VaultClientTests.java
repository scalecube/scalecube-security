package io.scalecube.security.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class VaultClientTests {

  private final List<Request> requests = new CopyOnWriteArrayList<>();
  private HttpServer server;

  private record Request(
      String method, String path, Map<String, List<String>> headers, String body) {}

  @BeforeEach
  void beforeEach() throws IOException {
    server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    server.start();
  }

  @AfterEach
  void afterEach() {
    server.stop(0);
  }

  @Test
  void testGetSendsVaultHeaders() throws Exception {
    respond("/v1/identity/oidc/token/role1", 200, "{\"data\":{\"token\":\"t\"}}");

    final var json =
        newClient(address())
            .get("vault-token", "identity", "oidc", "token", "role1")
            .get(3, TimeUnit.SECONDS);

    assertEquals("t", json.path("data").path("token").textValue());
    final var request = requests.get(0);
    assertEquals("GET", request.method());
    assertEquals(List.of("vault-token"), request.headers().get("X-vault-token"));
    assertEquals(List.of("true"), request.headers().get("X-vault-request"));
  }

  @Test
  void testPostSendsJsonBody() throws Exception {
    respond("/v1/identity/oidc/key/key1", 204, "");

    newClient(address())
        .post("t", Map.of("allowed_client_ids", List.of("*")), "identity", "oidc", "key", "key1")
        .get(3, TimeUnit.SECONDS);

    final var request = requests.get(0);
    assertEquals("POST", request.method());
    assertEquals("{\"allowed_client_ids\":[\"*\"]}", request.body());
    assertEquals(List.of("application/json"), request.headers().get("Content-type"));
  }

  @Test
  void testSuccessWithWarnings() throws Exception {
    // 200 (not 204) is returned when there are warnings
    respond("/v1/a", 200, "{\"warnings\":[\"w\"]}");

    final var json = newClient(address()).post("t", Map.of(), "a").get(3, TimeUnit.SECONDS);

    assertEquals("w", json.path("warnings").get(0).textValue());
  }

  @Test
  void testErrorResponse() {
    respond("/v1/a", 400, "{\"errors\":[\"first\",\"second\"]}");

    final var ex = assertVaultError(newClient(address()).get("t", "a"), 400);

    assertEquals(List.of("first", "second"), ex.errors());
  }

  @Test
  void testNonJsonErrorResponse() {
    respond("/v1/a", 502, "<html>bad gateway</html>");

    final var ex = assertVaultError(newClient(address()).get("t", "a"), 502);

    assertEquals(List.of("<html>bad gateway</html>"), ex.errors());
  }

  @Test
  void testRedirectIsFollowedWithMethodAndBody() throws Exception {
    // https://developer.hashicorp.com/vault/docs/concepts/ha#client-redirection
    respond("/v1/standby", 307, "", address() + "/v1/active");
    respond("/v1/active", 204, "");

    newClient(address()).post("t", Map.of("k", "v"), "standby").get(3, TimeUnit.SECONDS);

    assertEquals(2, requests.size());
    final var redirected = requests.get(1);
    assertEquals("/v1/active", redirected.path());
    assertEquals("POST", redirected.method());
    assertEquals("{\"k\":\"v\"}", redirected.body());
    assertEquals(List.of("t"), redirected.headers().get("X-vault-token"));
  }

  @Test
  void testAddressIsNormalized() throws Exception {
    respond("/v1/a", 204, "");

    newClient(address() + "//").get("t", "a").get(3, TimeUnit.SECONDS);

    assertEquals("/v1/a", requests.get(0).path());
  }

  @Test
  void testAddressWithPathPrefix() throws Exception {
    respond("/vault/v1/a", 204, "");

    newClient(address() + "/vault").get("t", "a").get(3, TimeUnit.SECONDS);

    assertEquals("/vault/v1/a", requests.get(0).path());
  }

  @Test
  void testInvalidAddress() {
    assertThrows(IllegalArgumentException.class, () -> newClient("localhost:8200"));
    assertThrows(IllegalArgumentException.class, () -> newClient("ftp://localhost:8200"));
    assertThrows(IllegalArgumentException.class, () -> newClient(address() + "?a=b"));
    assertThrows(IllegalArgumentException.class, () -> newClient(address() + "/vault#x"));
  }

  @Test
  void testNonCanonicalPathSegments() {
    final var client = newClient(address());
    for (var segment : new String[] {"", ".", "..", "a/b", "role."}) {
      assertThrows(IllegalArgumentException.class, () -> client.get("t", "a", segment), segment);
    }
  }

  @Test
  void testPathSegmentIsEncoded() throws Exception {
    respond("/v1/a b", 204, "");

    newClient(address()).get("t", "a b").get(3, TimeUnit.SECONDS);

    assertEquals("/v1/a b", requests.get(0).path());
  }

  @Test
  void testRequestTimeout() {
    server.createContext(
        "/v1/slow",
        httpCall -> {
          try {
            Thread.sleep(2000);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          httpCall.sendResponseHeaders(204, -1);
          httpCall.close();
        });
    final var client =
        new VaultClient(
            address(), VaultClient.newHttpClient(Duration.ofSeconds(1)), Duration.ofMillis(200));

    final var ex =
        assertThrows(
            ExecutionException.class, () -> client.get("t", "slow").get(3, TimeUnit.SECONDS));

    assertInstanceOf(HttpTimeoutException.class, ex.getCause());
  }

  private VaultClient newClient(String address) {
    return new VaultClient(
        address, VaultClient.newHttpClient(Duration.ofSeconds(1)), Duration.ofSeconds(1));
  }

  private String address() {
    return "http://localhost:" + server.getAddress().getPort();
  }

  private void respond(String path, int status, String body) {
    respond(path, status, body, null);
  }

  private void respond(String path, int status, String body, String location) {
    server.createContext(
        path,
        httpCall -> {
          requests.add(
              new Request(
                  httpCall.getRequestMethod(),
                  httpCall.getRequestURI().getPath(),
                  Map.copyOf(httpCall.getRequestHeaders()),
                  new String(httpCall.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
          if (location != null) {
            httpCall.getResponseHeaders().add("Location", location);
          }
          final var bytes = body.getBytes(StandardCharsets.UTF_8);
          httpCall.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
          if (bytes.length > 0) {
            try (var os = httpCall.getResponseBody()) {
              os.write(bytes);
            }
          }
          httpCall.close();
        });
  }

  private static VaultRequestException assertVaultError(
      CompletableFuture<?> future, int statusCode) {
    final var ex = assertThrows(ExecutionException.class, () -> future.get(3, TimeUnit.SECONDS));
    final var cause = assertInstanceOf(VaultRequestException.class, ex.getCause());
    assertEquals(statusCode, cause.statusCode());
    assertTrue(cause.getMessage().contains("status=" + statusCode), cause.getMessage());
    return cause;
  }
}
