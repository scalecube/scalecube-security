package io.scalecube.security.tokens.jwt;

import java.util.Map;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface JwtTokenResolver {

  /**
   * Verifies and returns token claims if everything went ok.
   *
   * @param token jwt token
   * @return mono result with parsed claims (or error)
   */
  Mono<Map<String, Object>> resolve(String token);
}
