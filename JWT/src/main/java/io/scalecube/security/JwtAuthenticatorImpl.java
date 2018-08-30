package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

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

    Jws<Claims> claims =
        Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);

    Claims tokenClaims = claims.getBody();

    return new Profile(tokenClaims.get("sub", String.class), tokenClaims.get("aud", String.class),
        tokenClaims.get("email", String.class), tokenClaims.get("email_verified", Boolean.class),
        tokenClaims.get("name", String.class), tokenClaims.get("family_name", String.class),
        tokenClaims.get("given_name", String.class), tokenClaims);
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
