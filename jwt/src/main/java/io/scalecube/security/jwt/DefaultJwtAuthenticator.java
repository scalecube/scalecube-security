package io.scalecube.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.scalecube.security.api.Profile;
import java.util.Map;
import reactor.core.publisher.Mono;

public final class DefaultJwtAuthenticator implements JwtAuthenticator {

  private final JwtKeyResolver jwtKeyResolver;

  public DefaultJwtAuthenticator(JwtKeyResolver jwtKeyResolver) {
    this.jwtKeyResolver = jwtKeyResolver;
  }

  @Override
  public Mono<Profile> authenticate(String token) {
    return Mono.defer(
        () -> {
          String tokenWithoutSignature = token.substring(0, token.lastIndexOf(".") + 1);

          JwtParser parser = Jwts.parser();

          Jwt<Header, Claims> claims = parser.parseClaimsJwt(tokenWithoutSignature);

          return jwtKeyResolver
              .resolve((Map<String, Object>) claims.getHeader())
              .map(key -> parser.setSigningKey(key).parseClaimsJws(token).getBody())
              .map(this::profileFromClaims);
        })
        .onErrorMap(AuthenticationException::new);
  }
}
