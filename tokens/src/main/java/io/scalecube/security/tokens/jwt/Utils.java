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

  static Key toRsaPublicKey(String n, String e) {
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

  static String mask(String data) {
    if (data == null || data.isEmpty() || data.length() < 5) {
      return "*****";
    }

    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
