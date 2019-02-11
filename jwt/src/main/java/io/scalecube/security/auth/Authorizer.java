package io.scalecube.security.auth;

import io.scalecube.security.Profile;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface Authorizer {
  Mono<Profile> authorize(Profile profile, String action);
}