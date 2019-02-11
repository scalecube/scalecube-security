package io.scalecube.security;

import java.security.Key;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface AsyncJwtKeyResolver {

  Mono<Key> resolve(String keyId);
}
