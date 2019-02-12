package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@SuppressWarnings("rawtypes")
public final class AsyncJwtAuthenticator implements JwtAuthenticator {

  private final AsyncJwtKeyResolver jwtKeyResolver;
  private static final JwtParser jwtParser = Jwts.parser();

  public AsyncJwtAuthenticator(AsyncJwtKeyResolver jwtKeyResolver) {
    this.jwtKeyResolver = jwtKeyResolver;
  }

  @Override
  public Mono<Profile> authenticate(String token) {
    return Mono.just(token)
        .map(AsyncJwtAuthenticator::jwtFromJwsToken)
        .map(AsyncJwtAuthenticator::parseClaimsFromJwt)
        .map(AsyncJwtAuthenticator::keyIdFromClaims)
        .flatMap(jwtKeyResolver::resolve)
        .map(Jwts.parser()::setSigningKey)
        .map(jwsParser -> jwsParser.parseClaimsJws(token))
        .map(Jws<Claims>::getBody)
        .map(this::profileFromClaims);
  }

  private static String jwtFromJwsToken(String token) {
    return token.substring(0, token.lastIndexOf('.') - 1);
  }

  @SuppressWarnings("rawtypes")
  private static Jwt<Header, Claims> parseClaimsFromJwt(String noSignatureToken) {
    return jwtParser.parseClaimsJwt(noSignatureToken);
  }

  @SuppressWarnings("unchecked")
  private static String keyIdFromClaims(Jwt<Header, Claims> claims) {
    return claims.getHeader().getOrDefault("kid", "").toString();
  }
}
