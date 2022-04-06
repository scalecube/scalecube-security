package io.scalecube.security.tokens.jwt;

import java.util.Map;
import reactor.core.publisher.Mono;

public interface JwtTokenResolver {

  /**
   * Parses and returns token claims without verification.
   *
   * @param token jwt token
   * @return parsed claims
   */
  Map<String, Object> parseBody(String token);

  /**
   * Verifies and returns token claims if everything went ok.
   *
   * @param token jwt token
   * @return mono result with parsed claims (or error)
   */
  Mono<Map<String, Object>> resolve(String token);
}
