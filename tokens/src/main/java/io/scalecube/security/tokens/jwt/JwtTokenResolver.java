package io.scalecube.security.tokens.jwt;

import java.util.concurrent.CompletableFuture;

public interface JwtTokenResolver {

  /**
   * Verifies given JWT and parses its header and claims.
   *
   * @param token jwt token
   * @return async result with {@link JwtToken}, or error
   */
  CompletableFuture<JwtToken> resolve(String token);

  /**
   * Parses given JWT without verifying its signature.
   *
   * @param token jwt token
   * @return parsed token
   */
  JwtToken parse(String token);
}
