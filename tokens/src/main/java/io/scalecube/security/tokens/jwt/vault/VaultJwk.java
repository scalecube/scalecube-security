package io.scalecube.security.tokens.jwt.vault;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.StringJoiner;

public class VaultJwk {

  private String use;
  private String kty;
  private String kid;
  private String alg;

  @JsonProperty("n")
  private String modulus; // n

  @JsonProperty("e")
  private String exponent; // e

  /**
   * Serialization only constructor.
   *
   * @deprecated not to be used
   */
  public VaultJwk() {}

  public String use() {
    return use;
  }

  public String kty() {
    return kty;
  }

  public String kid() {
    return kid;
  }

  public String alg() {
    return alg;
  }

  public String modulus() {
    return modulus;
  }

  public String exponent() {
    return exponent;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", VaultJwk.class.getSimpleName() + "[", "]")
        .add("use='" + use + "'")
        .add("kty='" + kty + "'")
        .add("kid='" + kid + "'")
        .add("alg='" + alg + "'")
        .add("n='" + modulus + "'")
        .add("e='" + exponent + "'")
        .toString();
  }
}
