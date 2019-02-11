package io.scalecube.security;

import io.scalecube.security.auth.Authenticator;
import reactor.core.publisher.Mono;

public interface JwtAuthenticator extends Authenticator {

  /**
   * Authenticate a JWT token.
   *
   * @param token jwt token.
   * @return security profile.
   */
  Mono<Profile> authenticate(String token);
}
