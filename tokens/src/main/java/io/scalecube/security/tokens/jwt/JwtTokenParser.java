package io.scalecube.security.tokens.jwt;

import java.security.Key;

public interface JwtTokenParser {

  JwtToken parseToken();

  JwtToken verifyToken(Key key);
}
