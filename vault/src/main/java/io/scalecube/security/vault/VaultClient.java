package io.scalecube.security.vault;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Minimal client of the Vault HTTP API (https://developer.hashicorp.com/vault/api-docs), covering
 * only what this module needs. Follows the API reference conventions, not a particular Vault
 * version:
 *
 * <ul>
 *   <li>token in {@code X-Vault-Token}, and {@code X-Vault-Request: true} on every request
 *       (required by Vault Proxy with {@code require_request_header}, always sent by the official
 *       clients);
 *   <li>{@code 200} and {@code 204} are success, anything else is {@link VaultRequestException}
 *       with the messages from {@code {"errors": [...]}} (also thrown for a success response with
 *       invalid json);
 *   <li>redirects (e.g. {@code 307} from a standby node when request forwarding is off) are
 *       followed with method and body preserved; the JDK client never follows https to http;
 *   <li>request paths are canonical: no empty, {@code .} or {@code ..} segments, no segment ending
 *       with a period.
 * </ul>
 *
 * <p>No retries: callers decide whether and how to retry.
 */
class VaultClient {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  private static final String VAULT_REQUEST_HEADER = "X-Vault-Request";
  private static final int MAX_ERROR_BODY_LENGTH = 512;

  private final String baseUri;
  private final HttpClient httpClient;
  private final Duration requestTimeout;

  VaultClient(String vaultAddress, HttpClient httpClient, Duration requestTimeout) {
    this.baseUri = normalizeAddress(vaultAddress) + "/v1";
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
  }

  static HttpClient newHttpClient(Duration connectTimeout) {
    return HttpClient.newBuilder()
        .version(Version.HTTP_1_1)
        .followRedirects(Redirect.NORMAL)
        .connectTimeout(Objects.requireNonNull(connectTimeout, "connectTimeout"))
        .build();
  }

  CompletableFuture<JsonNode> get(String vaultToken, String... pathSegments) {
    return send(newRequest(vaultToken, pathSegments).GET().build());
  }

  CompletableFuture<JsonNode> post(String vaultToken, Object body, String... pathSegments) {
    final String json;
    try {
      json = OBJECT_MAPPER.writeValueAsString(body);
    } catch (JsonProcessingException e) {
      return CompletableFuture.failedFuture(e);
    }
    return send(
        newRequest(vaultToken, pathSegments)
            .header("Content-Type", "application/json")
            .POST(BodyPublishers.ofString(json, StandardCharsets.UTF_8))
            .build());
  }

  private HttpRequest.Builder newRequest(String vaultToken, String... pathSegments) {
    return HttpRequest.newBuilder(URI.create(baseUri + toPath(pathSegments)))
        .timeout(requestTimeout)
        .header(VAULT_TOKEN_HEADER, Objects.requireNonNull(vaultToken, "vaultToken"))
        .header(VAULT_REQUEST_HEADER, "true");
  }

  private CompletableFuture<JsonNode> send(HttpRequest request) {
    final var description = request.method() + " " + request.uri().getRawPath();
    return httpClient
        .sendAsync(request, BodyHandlers.ofString(StandardCharsets.UTF_8))
        .thenApply(response -> toJson(response, description));
  }

  private static JsonNode toJson(HttpResponse<String> response, String request) {
    final var statusCode = response.statusCode();
    final var body = response.body();

    if (statusCode == 200 || statusCode == 204) {
      if (body == null || body.isBlank()) {
        return NullNode.getInstance();
      }
      try {
        return OBJECT_MAPPER.readTree(body);
      } catch (JsonProcessingException e) {
        throw new VaultRequestException(
            "Invalid response from vault: " + request, statusCode, List.of(truncate(body)));
      }
    }

    throw new VaultRequestException("Vault request failed: " + request, statusCode, toErrors(body));
  }

  private static List<String> toErrors(String body) {
    if (body == null || body.isBlank()) {
      return List.of();
    }
    try {
      final var errors = OBJECT_MAPPER.readTree(body).get("errors");
      if (errors != null && errors.isArray()) {
        final var list = new ArrayList<String>();
        errors.forEach(error -> list.add(error.asText()));
        return list;
      }
    } catch (JsonProcessingException e) {
      // not json (e.g. html from a proxy), fall through
    }
    return List.of(truncate(body));
  }

  private static String truncate(String body) {
    return body.length() > MAX_ERROR_BODY_LENGTH
        ? body.substring(0, MAX_ERROR_BODY_LENGTH) + "..."
        : body;
  }

  private static String toPath(String... pathSegments) {
    final var sb = new StringBuilder();
    for (var segment : pathSegments) {
      if (segment == null || segment.isEmpty() || segment.contains("/") || segment.endsWith(".")) {
        throw new IllegalArgumentException("Invalid vault path segment: '" + segment + "'");
      }
      sb.append('/').append(URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20"));
    }
    return sb.toString();
  }

  private static String normalizeAddress(String vaultAddress) {
    var address = Objects.requireNonNull(vaultAddress, "vaultAddress").trim();
    while (address.endsWith("/")) {
      address = address.substring(0, address.length() - 1);
    }
    final var uri = URI.create(address);
    if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
        || uri.getHost() == null) {
      throw new IllegalArgumentException("Invalid vault address: " + vaultAddress);
    }
    return address;
  }
}
