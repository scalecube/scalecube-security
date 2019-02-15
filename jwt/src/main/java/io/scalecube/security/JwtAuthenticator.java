package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.scalecube.security.api.Authenticator;
import io.scalecube.security.api.Profile;
import reactor.core.publisher.Mono;

public interface JwtAuthenticator extends Authenticator {

  /**
   * Authenticate a JWT token.
   *
   * @param token jwt token.
   * @return security profile.
   */
  Mono<Profile> authenticate(String token);

  /**
   * Create a profile from claims.
   * @param tokenClaims the claims to parse
   * @return a profile from the claims
   */
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
