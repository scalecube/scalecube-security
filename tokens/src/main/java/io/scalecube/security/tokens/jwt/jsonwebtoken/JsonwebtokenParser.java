package io.scalecube.security.tokens.jwt.jsonwebtoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParserBuilder;
import io.scalecube.security.tokens.jwt.JwtToken;
import io.scalecube.security.tokens.jwt.JwtTokenParser;
import java.security.Key;

public class JsonwebtokenParser implements JwtTokenParser {

  private final String token;
  private final String justClaims;
  private final JwtParserBuilder parserBuilder;

  /**
   * Constructor.
   *
   * @param token jwt token
   * @param justClaims just claims
   * @param parserBuilder parser builder
   */
  public JsonwebtokenParser(String token, String justClaims, JwtParserBuilder parserBuilder) {
    this.token = token;
    this.justClaims = justClaims;
    this.parserBuilder = parserBuilder;
  }

  @Override
  public JwtToken parseToken() {
    //noinspection rawtypes
    Jwt<Header, Claims> jwt = parserBuilder.build().parseClaimsJwt(justClaims);
    //noinspection unchecked
    return new JwtToken(jwt.getHeader(), jwt.getBody());
  }

  @Override
  public JwtToken verifyToken(Key key) {
    Jws<Claims> jws = parserBuilder.setSigningKey(key).build().parseClaimsJws(token);
    //noinspection unchecked
    return new JwtToken(jws.getHeader(), jws.getBody());
  }
}
