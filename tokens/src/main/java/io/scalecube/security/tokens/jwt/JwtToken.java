package io.scalecube.security.tokens.jwt;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class JwtToken {

  private final Map<String, Object> header;
  private final Map<String, Object> body;

  public JwtToken(Map<String, Object> header, Map<String, Object> body) {
    this.header = Collections.unmodifiableMap(new HashMap<>(header));
    this.body = Collections.unmodifiableMap(new HashMap<>(body));
  }

  public Map<String, Object> header() {
    return header;
  }

  public Map<String, Object> body() {
    return body;
  }
}
