package io.scalecube.security.api;

import reactor.core.publisher.Mono;

@FunctionalInterface
public interface Authorizer {
  Mono<Profile> authorize(Profile profile, String action);
}
