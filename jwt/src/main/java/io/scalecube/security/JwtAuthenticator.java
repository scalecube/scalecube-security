package io.scalecube.security;

public interface JwtAuthenticator {

  Profile authenticate(String token);
}
