package io.scalecube.security.tokens.jwt;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import reactor.core.Exceptions;

public class Utils {

  private Utils() {
    // Do not instantiate
  }

  /**
   * Turns b64 url encoded {@code n} and {@code e} into RSA public key.
   *
   * @param n modulus (b64 url encoded)
   * @param e exponent (b64 url encoded)
   * @return RSA public key instance
   */
  public static Key toRsaPublicKey(String n, String e) {
    Decoder b64Decoder = Base64.getUrlDecoder();
    BigInteger modulus = new BigInteger(1, b64Decoder.decode(n));
    BigInteger exponent = new BigInteger(1, b64Decoder.decode(e));
    KeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
    try {
      return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    } catch (Exception ex) {
      throw Exceptions.propagate(ex);
    }
  }

  /**
   * Mask sensitive data by replacing part of string with an asterisk symbol.
   *
   * @param data sensitive data to be masked
   * @return masked data
   */
  public static String mask(String data) {
    if (data == null || data.isEmpty() || data.length() < 5) {
      return "*****";
    }

    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
