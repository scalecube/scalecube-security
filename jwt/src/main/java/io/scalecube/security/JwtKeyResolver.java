package io.scalecube.security;

import java.security.Key;
import java.util.Map;
import java.util.Optional;

@FunctionalInterface
public interface JwtKeyResolver {

  Optional<Key> resolve(Map<String, Object> tokenClaims);
}
