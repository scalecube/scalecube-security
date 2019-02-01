package io.scalecube.security;

public interface JwtAuthenticator {

  /**
   * Authenticate a JWT token.
   *
   * @param token jwt token.
   * @return security profile.
   */
  Profile authenticate(String token);
}
