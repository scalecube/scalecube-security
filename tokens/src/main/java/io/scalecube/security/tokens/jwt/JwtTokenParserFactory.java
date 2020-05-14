package io.scalecube.security.tokens.jwt;

public interface JwtTokenParserFactory {

  JwtTokenParser newParser(String token);
}
