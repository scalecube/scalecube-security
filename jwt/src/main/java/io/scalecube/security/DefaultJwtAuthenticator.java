package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

public final class DefaultJwtAuthenticator implements JwtAuthenticator {

  private final JwtParser jwtParser;

  public DefaultJwtAuthenticator(JwtKeyResolver jwtKeyResolver) {
    jwtParser = Jwts.parser().setSigningKeyResolver(new DefaultSigningKeyResolver(jwtKeyResolver));
  }

  @Override
  public Profile authenticate(String token) {
    Jws<Claims> claims;

    try {
      claims = jwtParser.parseClaimsJws(token);
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
}
