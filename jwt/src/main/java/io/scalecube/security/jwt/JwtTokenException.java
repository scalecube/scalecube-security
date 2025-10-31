package io.scalecube.security.jwt;

import java.util.StringJoiner;

/**
 * Generic exception type for JWT token resolution errors. Used as part {@link JwtTokenResolver}
 * mechanism, and responsible to abstract token resolution problems.
 */
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
