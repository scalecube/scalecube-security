package io.scalecube.security.api;

import reactor.core.publisher.Mono;

@FunctionalInterface
public interface Authenticator {
  /**
   * Authenticate the identity of one.
   *
   * @param token a string of identity, can be a token, a user & password etc,.
   * @return a mono with profile identifying the one, or mono with an error.
   */
  Mono<Profile> authenticate(String token);
}
