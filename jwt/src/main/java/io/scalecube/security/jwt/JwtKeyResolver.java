package io.scalecube.security.jwt;

import java.security.Key;
import java.util.Map;

@FunctionalInterface
public interface JwtKeyResolver {

  Key resolve(Map<String, Object> tokenClaims);
}
