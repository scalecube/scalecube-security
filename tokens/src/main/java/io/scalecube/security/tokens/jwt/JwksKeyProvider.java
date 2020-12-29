package io.scalecube.security.tokens.jwt;

import static io.scalecube.security.tokens.jwt.Utils.toRsaPublicKey;

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
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

public final class JwksKeyProvider implements KeyProvider {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwksKeyProvider.class);

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
  private static final Duration READ_TIMEOUT = Duration.ofSeconds(10);

  private static final ObjectMapper OBJECT_MAPPER = newObjectMapper();

  private final Scheduler scheduler;
  private final String jwksUri;
  private final long connectTimeoutMillis;
  private final long readTimeoutMillis;

  /**
   * Constructor.
   *
   * @param jwksUri jwksUri
   */
  public JwksKeyProvider(String jwksUri) {
    this(jwksUri, newScheduler(), CONNECT_TIMEOUT, READ_TIMEOUT);
  }

  /**
   * Constructor.
   *
   * @param jwksUri jwksUri
   * @param scheduler scheduler
   * @param connectTimeout connectTimeout
   * @param readTimeout readTimeout
   */
  public JwksKeyProvider(
      String jwksUri, Scheduler scheduler, Duration connectTimeout, Duration readTimeout) {
    this.jwksUri = jwksUri;
    this.scheduler = scheduler;
    this.connectTimeoutMillis = connectTimeout.toMillis();
    this.readTimeoutMillis = readTimeout.toMillis();
  }

  @Override
  public Mono<Key> findKey(String kid) {
    return computeKey(kid)
        .switchIfEmpty(Mono.error(new KeyNotFoundException("Key was not found, kid: " + kid)))
        .doOnSubscribe(s -> LOGGER.debug("[findKey] Looking up key in jwks, kid: {}", kid))
        .subscribeOn(scheduler);
  }

  private Mono<Key> computeKey(String kid) {
    return Mono.fromCallable(this::computeKeyList)
        .flatMap(list -> Mono.justOrEmpty(findRsaKey(list, kid)))
        .onErrorMap(th -> th instanceof KeyProviderException ? th : new KeyProviderException(th));
  }

  private JwkInfoList computeKeyList() throws IOException {
    HttpURLConnection httpClient = (HttpURLConnection) new URL(jwksUri).openConnection();
    httpClient.setConnectTimeout((int) connectTimeoutMillis);
    httpClient.setReadTimeout((int) readTimeoutMillis);

    int responseCode = httpClient.getResponseCode();
    if (responseCode != 200) {
      LOGGER.error("[computeKey][{}] Not expected response code: {}", jwksUri, responseCode);
      throw new KeyProviderException("Not expected response code: " + responseCode);
    }

    return toKeyList(httpClient.getInputStream());
  }

  private static JwkInfoList toKeyList(InputStream stream) {
    try (InputStream inputStream = new BufferedInputStream(stream)) {
      return OBJECT_MAPPER.readValue(inputStream, JwkInfoList.class);
    } catch (IOException e) {
      LOGGER.error("[toKeyList] Exception occurred: {}", e.toString());
      throw Exceptions.propagate(e);
    }
  }

  private Optional<Key> findRsaKey(JwkInfoList list, String kid) {
    return list.keys().stream()
        .filter(k -> kid.equals(k.kid()))
        .findFirst()
        .map(info -> toRsaPublicKey(info.modulus(), info.exponent()));
  }

  private static ObjectMapper newObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
    mapper.configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, true);
    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
    mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    return mapper;
  }

  private static Scheduler newScheduler() {
    return Schedulers.newElastic("jwks-key-provider", 60, true);
  }
}
