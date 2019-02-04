package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public final class DefaultJwtAuthenticator implements JwtAuthenticator {

  private SigningKeyResolver keyResolver;

  public DefaultJwtAuthenticator(JwtKeyResolver jwtKeyResolver) {
    keyResolver = new DefaultSigningKeyResolver(jwtKeyResolver);
  }

  @Override
  public Profile authenticate(String token) {
    Jws<Claims> claims;
    try {
      claims = Jwts.parser().setSigningKeyResolver(keyResolver).parseClaimsJws(token);
    } catch (ExpiredJwtException
        | UnsupportedJwtException
        | MalformedJwtException
        | SignatureException
        | IllegalArgumentException exception) {
      throw new AuthenticationException(exception);
    }

    Claims tokenClaims = claims.getBody();

    return Profile.builder()
        .userId(tokenClaims.get("sub", String.class))
        .tenant(tokenClaims.get("aud", String.class))
        .email(tokenClaims.get("email", String.class))
        .emailVerified(tokenClaims.get("email_verified", Boolean.class))
        .name(tokenClaims.get("name", String.class))
        .familyName(tokenClaims.get("family_name", String.class))
        .givenName(tokenClaims.get("given_name", String.class))
        .claims(tokenClaims)
        .build();
  }

  private static class DefaultSigningKeyResolver implements SigningKeyResolver {

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
}
