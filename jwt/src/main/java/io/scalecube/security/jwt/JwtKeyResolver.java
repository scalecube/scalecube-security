package io.scalecube.security.jwt;

import java.security.Key;
import java.util.Map;
import reactor.core.publisher.Mono;

@FunctionalInterface
public interface JwtKeyResolver {

  Mono<Key> resolve(Map<String, Object> jtwHeaders);
}
