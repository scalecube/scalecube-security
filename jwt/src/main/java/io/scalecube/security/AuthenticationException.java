package io.scalecube.security;

/**
 * This class encapsulates all authentication exceptions. This will allow us to replace the internal
 * mechanism of authentication without changing client code.
 */
public class AuthenticationException extends RuntimeException {

  public AuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }

  public AuthenticationException(Throwable cause) {
    super(cause.getMessage(), cause);
  }
}
