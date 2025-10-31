package io.scalecube.security.jwt;

import java.util.concurrent.CompletableFuture;

/**
 * Resolves and verifies JWT tokens asynchronously. Implementations parse the token, validate its
 * signature, and extract claims.
 */
public interface JwtTokenResolver {

  /**
   * Verifies given JWT and parses its header and claims.
   *
   * @param token jwt token
   * @return async result completing with {@link JwtToken}, or completing exceptionally with {@link
   *     JwtTokenException} on failure
   */
  CompletableFuture<JwtToken> resolveToken(String token);
}
