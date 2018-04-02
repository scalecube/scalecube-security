package io.scalecube.security;

public interface JWTAuthenticator {

    Profile authenticate(String token);
}
