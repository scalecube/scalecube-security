package io.scalecube.security.tokens.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonwebtokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JsonwebtokenResolver.class);

  private final Locator<Key> keyLocator;

  public JsonwebtokenResolver(Locator<Key> keyLocator) {
    this.keyLocator = Objects.requireNonNull(keyLocator, "keyLocator");
  }

  @Override
  public CompletableFuture<JwtToken> resolve(String token) {
    return CompletableFuture.supplyAsync(
            () -> {
              final var claimsJws =
                  Jwts.parser().keyLocator(keyLocator).build().parseSignedClaims(token);
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

  @Override
  public JwtToken parse(String token) {
    String[] parts = token.split("\\.");
    if (parts.length != 3) {
      throw new JwtTokenException("Invalid JWT format");
    }

    try {
      final var urlDecoder = Base64.getUrlDecoder();
      final var headerJson = new String(urlDecoder.decode(parts[0]), StandardCharsets.UTF_8);
      final var payloadJson = new String(urlDecoder.decode(parts[1]), StandardCharsets.UTF_8);

      final var mapper = new ObjectMapper();
      final var header = mapper.readValue(headerJson, Map.class);
      final var claims = mapper.readValue(payloadJson, Map.class);

      //noinspection unchecked
      return new JwtToken(header, claims);
    } catch (IOException e) {
      throw new JwtTokenException("Failed to decode JWT", e);
    }
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
