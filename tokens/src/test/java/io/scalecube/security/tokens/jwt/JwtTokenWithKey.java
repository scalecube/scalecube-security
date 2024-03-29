package io.scalecube.security.tokens.jwt;

import java.security.Key;
import java.util.Properties;

class JwtTokenWithKey {

  final String token;
  final Key key;
  final String kid;

  JwtTokenWithKey(String s) throws Exception {
    Properties props = new Properties();
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    props.load(classLoader.getResourceAsStream(s));
    this.token = props.getProperty("token");
    this.kid = props.getProperty("kid");
    this.key = JwksKeyProvider.toRsaPublicKey(props.getProperty("n"), props.getProperty("e"));
  }
}
