package io.scalecube.security.tokens.jwt;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import java.security.Key;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonwebtokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JsonwebtokenResolver.class);

  private final JwtParser jwtParser;

  public JsonwebtokenResolver(Locator<Key> keyLocator) {
    jwtParser = Jwts.parser().keyLocator(keyLocator).build();
  }

  @Override
  public CompletableFuture<JwtToken> resolveToken(String token) {
    return CompletableFuture.supplyAsync(
            () -> {
              final var claimsJws = jwtParser.parseSignedClaims(token);
              return new JwtToken(claimsJws.getHeader(), claimsJws.getPayload());
            })
        .handle(
            (jwtToken, ex) -> {
              if (jwtToken != null) {
                if (LOGGER.isDebugEnabled()) {
                  LOGGER.debug("Resolved JWT: {}", mask(token));
                }
                return jwtToken;
              }
              if (ex != null) {
                if (ex instanceof JwtTokenException) {
                  throw (JwtTokenException) ex;
                } else {
                  throw new JwtTokenException("Failed to resolve JWT: " + mask(token), ex);
                }
              }
              return null;
            });
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
