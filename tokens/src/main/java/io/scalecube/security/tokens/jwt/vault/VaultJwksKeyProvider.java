package io.scalecube.security.tokens.jwt.vault;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.scalecube.security.tokens.jwt.KeyProvider;
import io.scalecube.security.tokens.jwt.Utils;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

public final class VaultJwksKeyProvider implements KeyProvider {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultJwksKeyProvider.class);

  private final Scheduler scheduler = Schedulers.newSingle("vault-jwks", true);

  private final ObjectMapper mapper;

  private final String jwksUri;

  public VaultJwksKeyProvider(String jwksUri) {
    this.jwksUri = jwksUri;
    this.mapper = initMapper();
  }

  @Override
  public Mono<Key> findKey(String kid) {
    return Mono.defer(this::callJwksUri)
        .map(stream -> toRsaKey(stream, kid))
        .doOnSubscribe(s -> LOGGER.debug("[findKey] Looking up key in jwks, kid: {}", kid))
        .subscribeOn(scheduler);
  }

  private Mono<? extends InputStream> callJwksUri() {
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder().uri(URI.create(jwksUri)).build();
    return Mono.fromFuture(
        client.sendAsync(request, BodyHandlers.ofInputStream()).thenApply(HttpResponse::body));
  }

  private Key toRsaKey(InputStream stream, String kid) {
    return getKeyList(stream).keys().stream()
        .filter(k -> kid.equals(k.kid()))
        .filter(k -> "RSA".equals(k.kty())) // RSA
        .filter(k -> "sig".equals(k.use())) // signature
        .findFirst()
        .map(vaultJwk -> Utils.getRsaPublicKey(vaultJwk.modulus(), vaultJwk.exponent()))
        .orElseThrow(() -> new RuntimeException("Key was not found, kid: " + kid));
  }

  private VaultJwkList getKeyList(InputStream stream) {
    VaultJwkList list;
    try {
      list = mapper.readValue(stream, VaultJwkList.class);
    } catch (IOException e) {
      throw Exceptions.propagate(e);
    }
    return list;
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
