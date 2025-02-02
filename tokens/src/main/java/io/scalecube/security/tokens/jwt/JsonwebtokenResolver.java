package io.scalecube.security.tokens.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import java.security.Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

public class JsonwebtokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenResolver.class);

  private final Locator<Key> keyLocator;

  public JsonwebtokenResolver(Locator<Key> keyLocator) {
    this.keyLocator = keyLocator;
  }

  @Override
  public Mono<JwtToken> resolve(String token) {
    return Mono.fromCallable(
        () -> {
          final var claimsJws =
              Jwts.parser().keyLocator(keyLocator).build().parseSignedClaims(token);
          return new JwtToken(claimsJws.getHeader(), claimsJws.getPayload());
        });
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
