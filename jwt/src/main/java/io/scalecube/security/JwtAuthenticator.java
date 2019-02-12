package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.scalecube.security.auth.Authenticator;
import reactor.core.publisher.Mono;

public interface JwtAuthenticator extends Authenticator {

  /**
   * Authenticate a JWT token.
   *
   * @param token jwt token.
   * @return security profile.
   */
  Mono<Profile> authenticate(String token);
  
  default Profile profileFromClaims(Claims tokenClaims) {
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
