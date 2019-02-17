package io.scalecube.security.jwt;

import java.security.Key;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface AsyncJwtKeyResolver {

  Mono<Key> resolve(String keyId);
}
