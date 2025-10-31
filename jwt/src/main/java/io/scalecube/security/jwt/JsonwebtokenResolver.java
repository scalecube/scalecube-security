package io.scalecube.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonwebtokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JsonwebtokenResolver.class);

  private final JwksKeyLocator keyLocator;

  public JsonwebtokenResolver(JwksKeyLocator keyLocator) {
    this.keyLocator = keyLocator;
  }

  @Override
  public CompletableFuture<JwtToken> resolveToken(String token) {
    return CompletableFuture.supplyAsync(
            () -> {
              final var rawToken = JWT.decode(token);
              final var kid = rawToken.getKeyId();
              final var publicKey = (RSAPublicKey) keyLocator.locate(kid);
              final var verifier = JWT.require(Algorithm.RSA256(publicKey, null)).build();
              verifier.verify(token);
              return JwtToken.parseToken(token);
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
