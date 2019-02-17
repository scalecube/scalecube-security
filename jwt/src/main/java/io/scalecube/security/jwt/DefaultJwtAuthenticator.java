package io.scalecube.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.scalecube.security.api.Profile;
import reactor.core.publisher.Mono;

public final class DefaultJwtAuthenticator implements JwtAuthenticator {

  private final JwtParser jwtParser;

  public DefaultJwtAuthenticator(JwtKeyResolver jwtKeyResolver) {
    jwtParser = Jwts.parser().setSigningKeyResolver(new DefaultSigningKeyResolver(jwtKeyResolver));
  }

  @Override
  public Mono<Profile> authenticate(String token) {
    return Mono.just(token)
        .map(unparsedToken -> jwtParser.parseClaimsJws(unparsedToken))
        .map(Jws<Claims>::getBody)
        .map(this::profileFromClaims);
  }
}
