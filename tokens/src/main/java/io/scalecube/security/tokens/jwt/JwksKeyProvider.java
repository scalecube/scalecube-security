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
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public final class JwksKeyProvider implements KeyProvider {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwksKeyProvider.class);

  private static final ObjectMapper OBJECT_MAPPER = newObjectMapper();

  private String jwksUri;
  private Duration connectTimeout = Duration.ofSeconds(10);
  private Duration readTimeout = Duration.ofSeconds(10);

  public JwksKeyProvider() {}

  private JwksKeyProvider(JwksKeyProvider other) {
    this.jwksUri = other.jwksUri;
    this.connectTimeout = other.connectTimeout;
    this.readTimeout = other.readTimeout;
  }

  /**
   * Setter for jwksUri.
   *
   * @param jwksUri jwksUri
   * @return new instance with applied setting
   */
  public JwksKeyProvider jwksUri(String jwksUri) {
    final JwksKeyProvider c = copy();
    c.jwksUri = jwksUri;
    return c;
  }

  /**
   * Setter for connectTimeout.
   *
   * @param connectTimeout connectTimeout
   * @return new instance with applied setting
   */
  public JwksKeyProvider connectTimeout(Duration connectTimeout) {
    final JwksKeyProvider c = copy();
    c.connectTimeout = connectTimeout;
    return c;
  }

  /**
   * Setter for readTimeout.
   *
   * @param readTimeout readTimeout
   * @return new instance with applied setting
   */
  public JwksKeyProvider readTimeout(Duration readTimeout) {
    final JwksKeyProvider c = copy();
    c.readTimeout = readTimeout;
    return c;
  }

  @Override
  public Mono<Key> findKey(String kid) {
    return computeKey(kid)
        .switchIfEmpty(Mono.error(new KeyNotFoundException("Key was not found, kid: " + kid)))
        .doOnSubscribe(s -> LOGGER.debug("[findKey] Looking up key in jwks, kid: {}", kid))
        .subscribeOn(Schedulers.boundedElastic())
        .publishOn(Schedulers.boundedElastic());
  }

  private Mono<Key> computeKey(String kid) {
    return Mono.fromCallable(this::computeKeyList)
        .flatMap(list -> Mono.justOrEmpty(findRsaKey(list, kid)))
        .onErrorMap(th -> th instanceof KeyProviderException ? th : new KeyProviderException(th));
  }

  private JwkInfoList computeKeyList() throws IOException {
    HttpURLConnection httpClient = (HttpURLConnection) new URL(jwksUri).openConnection();
    httpClient.setConnectTimeout((int) connectTimeout.toMillis());
    httpClient.setReadTimeout((int) readTimeout.toMillis());

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

  static Key toRsaPublicKey(String n, String e) {
    Decoder b64Decoder = Base64.getUrlDecoder();
    BigInteger modulus = new BigInteger(1, b64Decoder.decode(n));
    BigInteger exponent = new BigInteger(1, b64Decoder.decode(e));
    KeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
    try {
      return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (Exception ex) {
      throw Exceptions.propagate(ex);
    }
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

  private JwksKeyProvider copy() {
    return new JwksKeyProvider(this);
  }
}
