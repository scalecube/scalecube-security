package io.scalecube.security.api;

import reactor.core.publisher.Mono;

public interface AccessControl {
  /**
   * Request for an action to be made.
   *
   * @param token or any kind of identifying string
   * @param resource the action name
   * @return A mono with active profile or with an error.
   */
  Mono<Profile> check(String token, String resource);
}
