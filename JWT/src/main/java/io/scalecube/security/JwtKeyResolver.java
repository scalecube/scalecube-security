package io.scalecube.security;

import java.security.Key;
import java.util.Optional;
import java.util.Map;

@FunctionalInterface
public interface JwtKeyResolver {

  Optional<Key> resolve(Map<String, Object> tokenClaims);
}
