package io.scalecube.security.jwt;

/**
 * Special JWT exception type indicating transient error during token resolution. For example such
 * transient errors are:
 *
 * <ul>
 *   <li>Key Rotation: JWKS endpoints often implement key rotation policies where keys are
 *       periodically changed for security reasons. If the JWT was issued with a "kid" that
 *       corresponds to a key that has since been rotated out, that key won't be available in the
 *       JWKS anymore.
 *   <li>Network or Server Issues: if the JWKS URI is temporarily down, inaccessible, or
 *       experiencing issues, cleint might not be able to retrieve the keys, or the list of keys
 *       might be incomplete or outdated.
 * </ul>
 */
public class JwtUnavailableException extends JwtTokenException {

  public JwtUnavailableException(String message) {
    super(message);
  }

  public JwtUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
