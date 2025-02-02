package io.scalecube.security.tokens.jwt;

import java.util.StringJoiner;

public class JwtTokenException extends RuntimeException {

  public JwtTokenException(String message) {
    super(message);
  }

  public JwtTokenException(String message, Throwable cause) {
    super(message, cause);
  }

  public JwtTokenException(Throwable cause) {
    super(cause);
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", getClass().getSimpleName() + "[", "]")
        .add("errorMessage='" + getMessage() + "'")
        .toString();
  }
}
