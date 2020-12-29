package io.scalecube.security.tokens.jwt;

public final class KeyNotFoundException extends RuntimeException {

  public KeyNotFoundException(String s) {
    super(s);
  }

  @Override
  public synchronized Throwable fillInStackTrace() {
    return this;
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + "{errorMessage=" + getMessage() + '}';
  }
}
