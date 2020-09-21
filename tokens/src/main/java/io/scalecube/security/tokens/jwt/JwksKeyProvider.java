package io.scalecube.security.tokens.jwt;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

public final class JwksKeyProvider implements KeyProvider {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwksKeyProvider.class);

  private final Scheduler scheduler = Schedulers.newSingle("jwks-key-provider", true);

  private final ObjectMapper mapper;
  private final String jwksUri;
  private final long connectTimeoutMillis;
  private final long readTimeoutMillis;

  /**
   * Constructor.
   *
   * @param jwksUri jwksUri
   */
  public JwksKeyProvider(String jwksUri) {
    this.jwksUri = jwksUri;
    this.mapper = initMapper();
    this.connectTimeoutMillis = Duration.ofSeconds(10).toMillis();
    this.readTimeoutMillis = Duration.ofSeconds(10).toMillis();
  }

  /**
   * Constructor.
   *
   * @param jwksUri jwksUri
   * @param connectTimeout connectTimeout
   * @param readTimeout readTimeout
   */
  public JwksKeyProvider(String jwksUri, Duration connectTimeout, Duration readTimeout) {
    this.jwksUri = jwksUri;
    this.mapper = initMapper();
    this.connectTimeoutMillis = connectTimeout.toMillis();
    this.readTimeoutMillis = readTimeout.toMillis();
  }

  @Override
  public Mono<Key> findKey(String kid) {
    return Mono.defer(this::callJwksUri)
        .map(this::toKeyList)
        .map(list -> findRsaKey(list, kid))
        .doOnSubscribe(s -> LOGGER.debug("[findKey] Looking up key in jwks, kid: {}", kid))
        .subscribeOn(scheduler)
        .publishOn(scheduler);
  }

  private Mono<InputStream> callJwksUri() {
    return Mono.fromCallable(
        () -> {
          HttpURLConnection httpClient = (HttpURLConnection) new URL(jwksUri).openConnection();
          httpClient.setConnectTimeout((int) connectTimeoutMillis);
          httpClient.setReadTimeout((int) readTimeoutMillis);

          int responseCode = httpClient.getResponseCode();
          if (responseCode == 204) {
            return null;
          }
          if (responseCode != 200) {
            LOGGER.error("[callJwksUri][{}] Not expected response code: {}", jwksUri, responseCode);
            throw new KeyProviderException("Not expected response code: " + responseCode);
          }

          return httpClient.getInputStream();
        });
  }

  private JwkInfoList toKeyList(InputStream stream) {
    try (InputStream inputStream = new BufferedInputStream(stream)) {
      return mapper.readValue(inputStream, JwkInfoList.class);
    } catch (IOException e) {
      LOGGER.error("[toKeyList] Exception occurred: {}", e.toString());
      throw new KeyProviderException(e);
    }
  }

  private Key findRsaKey(JwkInfoList list, String kid) {
    return list.keys().stream()
        .filter(k -> kid.equals(k.kid()))
        .findFirst()
        .map(vaultJwk -> Utils.getRsaPublicKey(vaultJwk.modulus(), vaultJwk.exponent()))
        .orElseThrow(() -> new KeyProviderException("Key was not found, kid: " + kid));
  }

  private static ObjectMapper initMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
    mapper.configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, true);
    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
    mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    return mapper;
  }
}
