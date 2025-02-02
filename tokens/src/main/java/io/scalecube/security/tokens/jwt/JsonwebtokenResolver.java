package io.scalecube.security.tokens.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import java.security.Key;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonwebtokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JsonwebtokenResolver.class);

  private final Locator<Key> keyLocator;

  public JsonwebtokenResolver(Locator<Key> keyLocator) {
    this.keyLocator = keyLocator;
  }

  @Override
  public CompletableFuture<JwtToken> resolve(String token) {
    return CompletableFuture.supplyAsync(
            () -> {
              if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Resolve token: {}", mask(token));
              }

              final var claimsJws =
                  Jwts.parser().keyLocator(keyLocator).build().parseSignedClaims(token);

              return new JwtToken(claimsJws.getHeader(), claimsJws.getPayload());
            })
        .whenComplete(
            (jwtToken, ex) -> {
              if (jwtToken != null) {
                if (LOGGER.isDebugEnabled()) {
                  LOGGER.debug("Resolved token: {}", mask(token));
                }
              }
              if (ex != null) {
                if (LOGGER.isWarnEnabled()) {
                  LOGGER.warn("Failed to resolve token: {}, cause: {}", mask(token), ex.toString());
                }
              }
            });
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
