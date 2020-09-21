package io.scalecube.security.tokens.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.StringJoiner;

public class JwkInfo {

  private String use;
  private String kty;
  private String kid;
  private String alg;

  @JsonProperty("n")
  private String modulus; // n

  @JsonProperty("e")
  private String exponent; // e

  public JwkInfo() {}

  /**
   * Constructor.
   *
   * @param use use
   * @param kty kty
   * @param kid kid
   * @param alg alg
   * @param modulus modulus
   * @param exponent exponent
   */
  public JwkInfo(String use, String kty, String kid, String alg, String modulus, String exponent) {
    this.use = use;
    this.kty = kty;
    this.kid = kid;
    this.alg = alg;
    this.modulus = modulus;
    this.exponent = exponent;
  }

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
    return new StringJoiner(", ", JwkInfo.class.getSimpleName() + "[", "]")
        .add("use='" + use + "'")
        .add("kty='" + kty + "'")
        .add("kid='" + kid + "'")
        .add("alg='" + alg + "'")
        .add("n='" + modulus + "'")
        .add("e='" + exponent + "'")
        .toString();
  }
}
