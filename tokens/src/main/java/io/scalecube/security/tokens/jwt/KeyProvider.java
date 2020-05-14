package io.scalecube.security.tokens.jwt;

import java.security.Key;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface KeyProvider {

  /**
   * Finds key for jwt token verification.
   *
   * @param kid key id token attribute
   * @return mono result with key (or error)
   */
  Mono<Key> findKey(String kid);
}
