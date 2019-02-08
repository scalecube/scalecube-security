package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

final class DefaultSigningKeyResolver implements SigningKeyResolver {

  private JwtKeyResolver keyResolver;

  DefaultSigningKeyResolver(JwtKeyResolver keyResolver) {
    if (keyResolver == null) {
      throw new IllegalArgumentException("keyResolver have to be not null");
    }

    this.keyResolver = keyResolver;
  }

  @Override
  public Key resolveSigningKey(JwsHeader header, Claims claims) {
    Map<String, Object> tokenClaims = new HashMap<>();
    tokenClaims.putAll(header);
    tokenClaims.putAll(claims);

    return keyResolver.resolve(tokenClaims);
  }

  @Override
  public Key resolveSigningKey(JwsHeader jwsHeader, String s) {
    throw new UnsupportedOperationException("Only JSON tokens are supported");
  }
}
