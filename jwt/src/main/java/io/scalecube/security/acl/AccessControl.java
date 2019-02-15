package io.scalecube.security.acl;

import io.scalecube.security.Profile;
import reactor.core.publisher.Mono;

public interface AccessControl {
  /**
   * Request for an action to be made.
   *
   * @param identity a token, or any kind of identifying string
   * @param action the action name
   * @return A mono with active profile or with an error.
   */
  Mono<Profile> access(String identity, String action);
}
