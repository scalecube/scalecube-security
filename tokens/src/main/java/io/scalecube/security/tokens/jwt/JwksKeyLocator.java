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
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public class JwksKeyLocator extends LocatorAdapter<Key> {

  private static final ObjectMapper OBJECT_MAPPER = newObjectMapper();

  private final URI jwksUri;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final int keyTtl;

  private final Map<String, CachedKey> keyResolutions = new ConcurrentHashMap<>();
  private final ReentrantLock cleanupLock = new ReentrantLock();

  private JwksKeyLocator(Builder builder) {
    this.jwksUri = builder.jwksUri;
    this.connectTimeout = builder.connectTimeout;
    this.requestTimeout = builder.requestTimeout;
    this.keyTtl = builder.keyTtl;
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
                  throw new JwtTokenException("Cannot find key by kid: " + kid);
                }
                return new CachedKey(key, System.currentTimeMillis() + keyTtl);
              })
          .key();
    } catch (JwtTokenException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new JwtTokenException(ex);
    } finally {
      tryCleanup();
    }
  }

  private JwkInfoList computeKeyList() {
    final HttpResponse<InputStream> httpResponse;
    try {
      httpResponse =
          HttpClient.newBuilder()
              .connectTimeout(connectTimeout)
              .build()
              .send(
                  HttpRequest.newBuilder(jwksUri).GET().timeout(requestTimeout).build(),
                  BodyHandlers.ofInputStream());
    } catch (Exception e) {
      throw new JwtTokenException("Failed to retrive jwk keys", e);
    }

    final var statusCode = httpResponse.statusCode();
    if (statusCode != 200) {
      throw new JwtTokenException("Failed to retrive jwk keys, status: " + statusCode);
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

    public Builder jwksUri(String jwksUri) {
      this.jwksUri = URI.create(jwksUri);
      return this;
    }

    public Builder connectTimeout(Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
      return this;
    }

    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    public Builder keyTtl(int keyTtl) {
      this.keyTtl = keyTtl;
      return this;
    }

    public JwksKeyLocator build() {
      return new JwksKeyLocator(this);
    }
  }
}
