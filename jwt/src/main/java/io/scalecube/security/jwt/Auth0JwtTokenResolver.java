package io.scalecube.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves and verifies JWT tokens using public keys provided by {@link JwksKeyProvider}. Tokens
 * are validated asynchronously and parsed into {@link JwtToken} instances. Only {@code RS256}
 * signed tokens are supported. Optionally, token issuer ({@code iss}) and audience ({@code aud})
 * are verified.
 */
public class Auth0JwtTokenResolver implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(Auth0JwtTokenResolver.class);

  private final JwksKeyProvider keyProvider;
  private final String issuer;
  private final String[] audience;
  private final Executor executor;

  private Auth0JwtTokenResolver(Builder builder) {
    this.keyProvider = Objects.requireNonNull(builder.keyProvider, "keyProvider");
    this.issuer = builder.issuer;
    this.audience = builder.audience;
    this.executor = Objects.requireNonNull(builder.executor, "executor");
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public CompletableFuture<JwtToken> resolveToken(String token) {
    return CompletableFuture.supplyAsync(() -> verifyToken(token), executor)
        .handle(
            (jwtToken, ex) -> {
              if (ex == null) {
                if (LOGGER.isDebugEnabled()) {
                  LOGGER.debug("Resolved JWT: {}", mask(token));
                }
                return jwtToken;
              }
              final var cause =
                  ex instanceof CompletionException && ex.getCause() != null ? ex.getCause() : ex;
              if (cause instanceof JwtTokenException) {
                throw (JwtTokenException) cause;
              }
              throw new JwtTokenException("Failed to resolve JWT: " + mask(token), cause);
            });
  }

  private JwtToken verifyToken(String token) {
    final var decodedToken = JWT.decode(token);
    final var key = keyProvider.getKey(decodedToken.getKeyId());
    if (!(key instanceof RSAPublicKey publicKey)) {
      throw new JwtTokenException("Unsupported key type, kid: " + decodedToken.getKeyId());
    }

    final var verification = JWT.require(Algorithm.RSA256(publicKey, null));
    if (issuer != null) {
      verification.withIssuer(issuer);
    }
    if (audience != null) {
      verification.withAudience(audience);
    }
    verification.build().verify(decodedToken);

    return JwtToken.parseToken(token);
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }

  public static class Builder {

    private JwksKeyProvider keyProvider;
    private String issuer;
    private String[] audience;
    private Executor executor = ForkJoinPool.commonPool();

    private Builder() {}

    public Builder keyProvider(JwksKeyProvider keyProvider) {
      this.keyProvider = keyProvider;
      return this;
    }

    /**
     * Setter for expected token issuer ({@code iss} claim).
     *
     * @param issuer issuer (optional, if not set {@code iss} claim is not verified)
     * @return this
     */
    public Builder issuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    /**
     * Setter for expected token audience ({@code aud} claim). Token is accepted if its {@code aud}
     * contains all given values.
     *
     * @param audience audience (optional, if not set {@code aud} claim is not verified)
     * @return this
     */
    public Builder audience(String... audience) {
      this.audience = audience;
      return this;
    }

    /**
     * Setter for {@link Executor} on which token verification (including possible JWKS fetch) is
     * executed.
     *
     * @param executor executor (optional, default is {@link ForkJoinPool#commonPool()})
     * @return this
     */
    public Builder executor(Executor executor) {
      this.executor = executor;
      return this;
    }

    public Auth0JwtTokenResolver build() {
      return new Auth0JwtTokenResolver(this);
    }
  }
}
