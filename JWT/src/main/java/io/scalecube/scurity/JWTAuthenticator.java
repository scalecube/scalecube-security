package io.scalecube.scurity;

public interface JWTAuthenticator {

    Profile authenticate(String token);

}
