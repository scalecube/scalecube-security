package io.scalecube.security;

import java.util.Optional;
import java.util.Map;

@FunctionalInterface
public interface JwtKeyResolver {

  Optional<byte[]> resolve(Map<String, Object> tokenClaims);
}
