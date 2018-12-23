package io.scalecube.security;

public class AuthenticationException extends RuntimeException {

  /**
   *  Generated serial Version UID.
   */
  private static final long serialVersionUID = 3524768727973503394L;

  public AuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }

  public AuthenticationException(Throwable cause) {
    super(cause.getMessage(), cause);
  }
}
