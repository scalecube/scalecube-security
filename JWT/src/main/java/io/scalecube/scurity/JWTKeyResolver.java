package io.scalecube.scurity;


import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

public interface JWTKeyResolver {

    Optional<byte[]> resolve(Supplier<Map<String,String>> tokenClaims);
}
