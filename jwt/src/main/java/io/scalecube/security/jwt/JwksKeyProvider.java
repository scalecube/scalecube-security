package io.scalecube.security.jwt;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Provides public keys from a remote JWKS endpoint and caches them temporarily. On lookup of a
 * {@code kid} that is not cached (or when cached key set has expired), the whole key set is
 * re-fetched, at most once per {@code minRefreshInterval}. Lookups of an unknown {@code kid} within
 * that interval fail fast with {@link JwtUnavailableException}, without remote calls.
 */
public class JwksKeyProvider {

  private static final ObjectMapper OBJECT_MAPPER = newObjectMapper();

  private final URI jwksUri;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final int keyTtl;
  private final long minRefreshInterval;
  private final HttpClient httpClient;

  private final ReentrantLock refreshLock = new ReentrantLock();
  private volatile KeySet keySet = new KeySet(Map.of(), Long.MIN_VALUE);
  private long lastRefreshTime;
  private boolean refreshed;

  private JwksKeyProvider(Builder builder) {
    this.jwksUri = Objects.requireNonNull(builder.jwksUri, "jwksUri");
    this.connectTimeout = Objects.requireNonNull(builder.connectTimeout, "connectTimeout");
    this.requestTimeout = Objects.requireNonNull(builder.requestTimeout, "requestTimeout");
    this.keyTtl = builder.keyTtl;
    this.minRefreshInterval =
        Objects.requireNonNull(builder.minRefreshInterval, "minRefreshInterval").toMillis();
    this.httpClient =
        builder.httpClient != null
            ? builder.httpClient
            : HttpClient.newBuilder().connectTimeout(connectTimeout).build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the public key for the given {@code kid}. If not cached, the key set is fetched from
   * the JWKS endpoint and cached for future use.
   *
   * @param kid key id of the public key to retrieve
   * @return {@link Key} object associated with given {@code kid}
   * @throws JwtUnavailableException if key cannot be found or JWKS cannot be retrieved
   */
  public Key getKey(String kid) {
    if (kid == null) {
      throw new JwtTokenException("Missing kid");
    }

    var key = keySet.find(kid, System.currentTimeMillis());
    if (key != null) {
      return key;
    }

    refreshLock.lock();
    try {
      final var now = System.currentTimeMillis();
      key = keySet.find(kid, now);
      if (key != null) {
        return key;
      }

      if (refreshed && now - lastRefreshTime < minRefreshInterval) {
        throw new JwtUnavailableException("Cannot find key by kid: " + kid);
      }

      refreshed = true;
      lastRefreshTime = now;
      keySet = new KeySet(fetchKeys(), now + keyTtl);

      key = keySet.find(kid, now);
      if (key == null) {
        throw new JwtUnavailableException("Cannot find key by kid: " + kid);
      }
      return key;
    } finally {
      refreshLock.unlock();
    }
  }

  private Map<String, Key> fetchKeys() {
    final HttpResponse<InputStream> httpResponse;
    try {
      httpResponse =
          httpClient.send(
              HttpRequest.newBuilder(jwksUri).GET().timeout(requestTimeout).build(),
              BodyHandlers.ofInputStream());
    } catch (IOException e) {
      throw new JwtUnavailableException("Failed to retrieve jwk keys", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new JwtTokenException("Interrupted while retrieving jwk keys", e);
    }

    try (var body = httpResponse.body()) {
      final var statusCode = httpResponse.statusCode();
      if (statusCode != 200) {
        throw new JwtUnavailableException("Failed to retrieve jwk keys, status: " + statusCode);
      }
      return toKeys(OBJECT_MAPPER.readValue(body, JwkInfoList.class));
    } catch (IOException e) {
      throw new JwtUnavailableException("Failed to read jwk keys", e);
    }
  }

  private static Map<String, Key> toKeys(JwkInfoList jwkInfoList) {
    final var keys = new HashMap<String, Key>();
    if (jwkInfoList.keys() != null) {
      for (var jwkInfo : jwkInfoList.keys()) {
        if (jwkInfo.kid() != null
            && "RSA".equals(jwkInfo.kty())
            && (jwkInfo.use() == null || "sig".equals(jwkInfo.use()))) {
          keys.put(jwkInfo.kid(), toRsaPublicKey(jwkInfo));
        }
      }
    }
    return Map.copyOf(keys);
  }

  private static PublicKey toRsaPublicKey(JwkInfo jwkInfo) {
    try {
      final var decoder = Base64.getUrlDecoder();
      final var modulus = new BigInteger(1, decoder.decode(jwkInfo.modulus()));
      final var exponent = new BigInteger(1, decoder.decode(jwkInfo.exponent()));
      final var keySpec = new RSAPublicKeySpec(modulus, exponent);
      return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (Exception ex) {
      throw new JwtTokenException("Invalid jwk, kid: " + jwkInfo.kid(), ex);
    }
  }

  private static ObjectMapper newObjectMapper() {
    final var mapper = new ObjectMapper();
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
    mapper.configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, true);
    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
    mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    return mapper;
  }

  private record KeySet(Map<String, Key> keys, long expirationDeadline) {

    Key find(String kid, long now) {
      return now < expirationDeadline ? keys.get(kid) : null;
    }
  }

  public static class Builder {

    private URI jwksUri;
    private Duration connectTimeout = Duration.ofSeconds(10);
    private Duration requestTimeout = Duration.ofSeconds(10);
    private int keyTtl = 60 * 1000;
    private Duration minRefreshInterval = Duration.ofSeconds(5);
    private HttpClient httpClient;

    private Builder() {}

    /**
     * Setter for JWKS URI. The JWKS URI typically follows a well-known pattern, such as {@code
     * https://server_domain/.well-known/jwks.json}. This endpoint is a read-only URL that responds
     * to GET requests by returning the JWKS in JSON format.
     *
     * @param jwksUri jwksUri
     * @return this
     */
    public Builder jwksUri(String jwksUri) {
      this.jwksUri = URI.create(jwksUri);
      return this;
    }

    /**
     * Setter for {@code connectTimeout}.
     *
     * @param connectTimeout connectTimeout (optional)
     * @return this
     */
    public Builder connectTimeout(Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
      return this;
    }

    /**
     * Setter for {@code requestTimeout}.
     *
     * @param requestTimeout requestTimeout (optional)
     * @return this
     */
    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    /**
     * Setter for {@code keyTtl}. Keys that was obtained from JWKS URI gets cached for some period
     * of time, after that they being removed from the cache. This caching time period is controlled
     * by {@code keyTtl} setting.
     *
     * @param keyTtl keyTtl in millis (optional)
     * @return this
     */
    public Builder keyTtl(int keyTtl) {
      this.keyTtl = keyTtl;
      return this;
    }

    /**
     * Setter for {@code minRefreshInterval}. Minimum time between two fetches of JWKS. Protects
     * JWKS endpoint (and callers) from being flooded by tokens with unknown {@code kid}.
     *
     * @param minRefreshInterval minRefreshInterval (optional)
     * @return this
     */
    public Builder minRefreshInterval(Duration minRefreshInterval) {
      this.minRefreshInterval = minRefreshInterval;
      return this;
    }

    /**
     * Setter for optional {@link HttpClient}.
     *
     * @param httpClient httpClient
     * @return this
     */
    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = httpClient;
      return this;
    }

    public JwksKeyProvider build() {
      return new JwksKeyProvider(this);
    }
  }
}
