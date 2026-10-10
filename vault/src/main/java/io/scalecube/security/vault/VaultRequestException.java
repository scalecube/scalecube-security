package io.scalecube.security.vault;

import java.util.List;

/**
 * Vault responded with an error status (anything other than {@code 200} or {@code 204}). Carries
 * the status code and the messages from Vault's error response ({@code {"errors": [...]}}).
 */
public class VaultRequestException extends RuntimeException {

  private final int statusCode;
  private final List<String> errors;

  public VaultRequestException(String message, int statusCode, List<String> errors) {
    super(message + ", status=" + statusCode + ", errors=" + errors);
    this.statusCode = statusCode;
    this.errors = List.copyOf(errors);
  }

  public int statusCode() {
    return statusCode;
  }

  public List<String> errors() {
    return errors;
  }
}
