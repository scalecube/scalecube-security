package io.scalecube.security.tokens.jwt;

import java.util.concurrent.CompletableFuture;

public interface JwtTokenResolver {

  /**
   * Verifies and returns token claims.
   *
   * @param token jwt token
   * @return mono result with parsed claims (or error)
   */
  CompletableFuture<JwtToken> resolve(String token);
}
