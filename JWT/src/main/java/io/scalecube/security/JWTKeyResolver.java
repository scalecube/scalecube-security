package io.scalecube.security;


import java.util.Map;
import java.util.Optional;

//TODO: add javadoc
@FunctionalInterface
public interface JWTKeyResolver {

    Optional<byte[]> resolve(Map<String,Object> tokenClaims);
}
