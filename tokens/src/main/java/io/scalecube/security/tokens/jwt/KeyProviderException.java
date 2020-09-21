package io.scalecube.security.tokens.jwt;

public final class KeyProviderException extends RuntimeException {

  public KeyProviderException() {}

  public KeyProviderException(String s) {
    super(s);
  }

  public KeyProviderException(String s, Throwable throwable) {
    super(s, throwable);
  }

  public KeyProviderException(Throwable throwable) {
    super(throwable);
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
