package io.scalecube.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.ProtectedHeader;
import java.security.Key;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves and verifies JWT tokens using public keys provided by {@link JwksKeyProvider}. Tokens
 * are validated asynchronously and parsed into {@link JwtToken} instances.
 */
public class JwksTokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwksTokenResolver.class);

  private final JwksKeyProvider keyProvider;

  public JwksTokenResolver(JwksKeyProvider keyProvider) {
    this.keyProvider = keyProvider;
  }

  @Override
  public CompletableFuture<JwtToken> resolveToken(String token) {
    return CompletableFuture.supplyAsync(
            () -> {
              final Jwt<?, ?> parse =
                  Jwts.parser()
                      .keyLocator(
                          new LocatorAdapter<>() {
                            @Override
                            protected Key locate(ProtectedHeader header) {
                              final var keyId = header.getKeyId();
                              return keyProvider.getKey(keyId);
                            }
                          })
                      .build()
                      .parse(token);

              parse.getHeader();

              // final var rawToken = JWT.decode(token);
              // final var kid = rawToken.getKeyId();
              // final var publicKey = (RSAPublicKey) keyProvider.getKey(kid);
              // final var verifier = JWT.require(Algorithm.RSA256(publicKey, null)).build();
              // verifier.verify(token);

              return new JwtToken(parse.getHeader(), (Claims) parse.getPayload());
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
