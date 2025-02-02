package io.scalecube.security.tokens.jwt;

import reactor.core.publisher.Mono;

public interface JwtTokenResolver {

  /**
   * Verifies and returns token claims.
   *
   * @param token jwt token
   * @return mono result with parsed claims (or error)
   */
  Mono<JwtToken> resolve(String token);
}
