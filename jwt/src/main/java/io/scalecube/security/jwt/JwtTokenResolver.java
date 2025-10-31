package io.scalecube.security.jwt;

import java.util.concurrent.CompletableFuture;

public interface JwtTokenResolver {

  /**
   * Verifies given JWT and parses its header and claims.
   *
   * @param token jwt token
   * @return async result with {@link JwtToken}, or error
   */
  CompletableFuture<JwtToken> resolveToken(String token);
}
