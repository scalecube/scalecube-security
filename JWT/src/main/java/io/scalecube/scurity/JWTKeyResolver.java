package io.scalecube.scurity;


import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

//TODO: is it a functional interface?
@FunctionalInterface
public interface JWTKeyResolver {

    Optional<byte[]> resolve(Map<String,Object> tokenClaims);
}
