package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.Optional;

public class JwtAuthenticatorImpl implements JwtAuthenticator {

  Optional<JwtKeyResolver> keyResolver;

  private JwtAuthenticatorImpl(Optional<JwtKeyResolver> keyResolver) {
    this.keyResolver = keyResolver;
  }

  /** 
   * Authenticate a JWT token using the provided {@link JwtKeyResolver}.
   */
  public Profile authenticate(String token) {

    SigningKeyResolver signingKeyResolver =
        SigningKeyResolvers.defaultSigningKeyResolver(keyResolver);

    Jws<Claims> claims;
    try {
      claims = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);
    } catch (ExpiredJwtException
        | UnsupportedJwtException
        | MalformedJwtException
        | SignatureException
        | IllegalArgumentException exception) {
      throw new AuthenticationException(exception);
    }

    Claims tokenClaims = claims.getBody();

    return new Profile.Builder()
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

  public static class Builder {

    Optional<JwtKeyResolver> keyResolver = Optional.empty();

    public Builder keyResolver(JwtKeyResolver keyResolver) {
      this.keyResolver = Optional.of(keyResolver);
      return this;
    }

    public JwtAuthenticator build() {
      return new JwtAuthenticatorImpl(keyResolver);
    }
  }
}
