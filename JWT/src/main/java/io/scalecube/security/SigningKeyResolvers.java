package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;

import java.security.Key;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SigningKeyResolvers {

  static SigningKeyResolver defaultSigningKeyResolver(Optional<JwtKeyResolver> keyResolver) {

    return new SigningKeyResolver() {

      private Key retreiveKey(JwsHeader header, Claims claims) {

        // No key resolver provided, return null to signal no key
        if (!keyResolver.isPresent()) {
          return null;
        }

        JwtKeyResolver actualResolver = keyResolver.get();

        Map<String, Object> tokenProperties = Stream.of(claims, (Map<String, Object>) header)
            .map(Map::entrySet)
            .flatMap(Collection::stream)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        Optional<Key> jwtKey = actualResolver.resolve(tokenProperties);

        return jwtKey.orElse(null);
      }

      @Override
      public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return retreiveKey(header, claims);
      }

      @Override
      public Key resolveSigningKey(JwsHeader header, String plaintext) {
        throw new UnsupportedOperationException(); // Will only occur in case the token isn't json.
      }
    };
  }
}

