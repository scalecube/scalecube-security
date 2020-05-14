package io.scalecube.security.tokens.jwt.jsonwebtoken;

import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.scalecube.security.tokens.jwt.JwtTokenParser;
import io.scalecube.security.tokens.jwt.JwtTokenParserFactory;

public class JsonwebtokenParserFactory implements JwtTokenParserFactory {

  @Override
  public JwtTokenParser newParser(String token) {
    String justClaims = token.substring(0, token.lastIndexOf(".") + 1);
    JwtParserBuilder parserBuilder = Jwts.parserBuilder();
    return new JsonwebtokenParser(token, justClaims, parserBuilder);
  }
}
