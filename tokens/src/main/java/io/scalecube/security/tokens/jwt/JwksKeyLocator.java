package io.scalecube.security.tokens.jwt;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.HttpTimeoutException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public class JwksKeyLocator extends LocatorAdapter<Key> {

  private static final ObjectMapper OBJECT_MAPPER = newObjectMapper();

  private final URI jwksUri;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final int keyTtl;
  private final HttpClient httpClient;

  private final Map<String, CachedKey> keyResolutions = new ConcurrentHashMap<>();
  private final ReentrantLock cleanupLock = new ReentrantLock();

  private JwksKeyLocator(Builder builder) {
    this.jwksUri = Objects.requireNonNull(builder.jwksUri, "jwksUri");
    this.connectTimeout = Objects.requireNonNull(builder.connectTimeout, "connectTimeout");
    this.requestTimeout = Objects.requireNonNull(builder.requestTimeout, "requestTimeout");
    this.keyTtl = builder.keyTtl;
    this.httpClient = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  protected Key locate(JwsHeader header) {
    try {
      return keyResolutions
          .computeIfAbsent(
              header.getKeyId(),
              kid -> {
                final var key = findKeyById(computeKeyList(), kid);
                if (key == null) {
                  throw new JwtUnavailableException("Cannot find key by kid: " + kid);
                }
                return new CachedKey(key, System.currentTimeMillis() + keyTtl);
              })
          .key();
    } finally {
      tryCleanup();
    }
  }

  private JwkInfoList computeKeyList() {
    final HttpResponse<InputStream> httpResponse;
    try {
      httpResponse =
          httpClient.send(
              HttpRequest.newBuilder(jwksUri).GET().timeout(requestTimeout).build(),
              BodyHandlers.ofInputStream());
    } catch (HttpTimeoutException e) {
      throw new JwtUnavailableException("Failed to retrive jwk keys", e);
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }

    final var statusCode = httpResponse.statusCode();
    if (statusCode != 200) {
      throw new RuntimeException("Failed to retrive jwk keys, status: " + statusCode);
    }

    return toJwkInfoList(httpResponse.body());
  }

  private static JwkInfoList toJwkInfoList(InputStream stream) {
    try (var inputStream = new BufferedInputStream(stream)) {
      return OBJECT_MAPPER.readValue(inputStream, JwkInfoList.class);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static PublicKey findKeyById(JwkInfoList jwkInfoList, String kid) {
    if (jwkInfoList.keys() != null) {
      return jwkInfoList.keys().stream()
          .filter(jwkInfo -> kid.equals(jwkInfo.kid()))
          .map(jwkInfo -> toRsaPublicKey(jwkInfo.modulus(), jwkInfo.exponent()))
          .findFirst()
          .orElse(null);
    }
    return null;
  }

  private static PublicKey toRsaPublicKey(String n, String e) {
    final var decoder = Base64.getUrlDecoder();
    final var modulus = new BigInteger(1, decoder.decode(n));
    final var exponent = new BigInteger(1, decoder.decode(e));
    final var keySpec = new RSAPublicKeySpec(modulus, exponent);
    try {
      return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (Exception ex) {
      throw new RuntimeException(e);
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

  private void tryCleanup() {
    if (cleanupLock.tryLock()) {
      final var now = System.currentTimeMillis();
      try {
        keyResolutions.entrySet().removeIf(entry -> entry.getValue().hasExpired(now));
      } finally {
        cleanupLock.unlock();
      }
    }
  }

  private record CachedKey(Key key, long expirationDeadline) {

    boolean hasExpired(long now) {
      return now >= expirationDeadline;
    }
  }

  public static class Builder {

    private URI jwksUri;
    private Duration connectTimeout = Duration.ofSeconds(10);
    private Duration requestTimeout = Duration.ofSeconds(10);
    private int keyTtl = 60 * 1000;

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
     * @param keyTtl keyTtl (optional)
     * @return this
     */
    public Builder keyTtl(int keyTtl) {
      this.keyTtl = keyTtl;
      return this;
    }

    public JwksKeyLocator build() {
      return new JwksKeyLocator(this);
    }
  }
}
