package io.scalecube.security.tokens.jwt;

public final class KeyProviderException extends RuntimeException {

  public KeyProviderException(String s) {
    super(s);
  }

  public KeyProviderException(Throwable cause) {
    super(cause);
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
