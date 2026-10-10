package io.scalecube.security.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class JwksKeyProviderTests {

  private static final String ISSUER = "https://issuer";
  private static final String AUDIENCE = "api";

  private final KeyPair keyPair = newKeyPair();
  private final AtomicInteger fetchCount = new AtomicInteger();
  private final AtomicInteger status = new AtomicInteger(200);
  private final AtomicReference<String> jwks = new AtomicReference<>();
  private HttpServer server;

  @BeforeEach
  void beforeEach() throws Exception {
    jwks.set(jwks(rsaJwk("kid-1", keyPair)));
    server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    server.createContext(
        "/jwks",
        exchange -> {
          fetchCount.incrementAndGet();
          final var body = jwks.get().getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(status.get(), body.length);
          try (var os = exchange.getResponseBody()) {
            os.write(body);
          }
        });
    server.start();
  }

  @AfterEach
  void afterEach() {
    server.stop(0);
  }

  @Test
  void testResolveToken() throws Exception {
    final var jwtToken = newResolver().resolveToken(newToken("kid-1")).get(3, TimeUnit.SECONDS);

    assertNotNull(jwtToken);
    assertEquals(ISSUER, jwtToken.payload().get("iss"));
  }

  @Test
  void testUnknownKidIsUnavailableAndFetchedOncePerInterval() {
    final var resolver = newResolver();

    for (int i = 0; i < 20; i++) {
      final var cause = resolveError(resolver, newToken(UUID.randomUUID().toString()));
      assertInstanceOf(JwtUnavailableException.class, cause);
    }

    assertEquals(1, fetchCount.get());
  }

  @Test
  void testKnownKeyDoesNotRefetch() throws Exception {
    final var resolver = newResolver();

    for (int i = 0; i < 5; i++) {
      resolver.resolveToken(newToken("kid-1")).get(3, TimeUnit.SECONDS);
    }

    assertEquals(1, fetchCount.get());
  }

  @Test
  void testRotatedKeyIsFetchedAfterInterval() throws Exception {
    final var resolver = newResolver(Duration.ofMillis(200));
    resolver.resolveToken(newToken("kid-1")).get(3, TimeUnit.SECONDS);

    final var newKeyPair = newKeyPair();
    jwks.set(jwks(rsaJwk("kid-1", keyPair), rsaJwk("kid-2", newKeyPair)));
    Thread.sleep(300);

    final var token = newToken("kid-2", newKeyPair, ISSUER, AUDIENCE);
    assertNotNull(resolver.resolveToken(token).get(3, TimeUnit.SECONDS));
    assertEquals(2, fetchCount.get());
  }

  @Test
  void testServerErrorIsUnavailable() {
    status.set(503);

    assertInstanceOf(JwtUnavailableException.class, resolveError(newResolver(), newToken("kid-1")));
  }

  @Test
  void testConnectionRefusedIsUnavailable() {
    server.stop(0);

    assertInstanceOf(JwtUnavailableException.class, resolveError(newResolver(), newToken("kid-1")));
  }

  @Test
  void testNonRsaKeyIsIgnored() {
    jwks.set(jwks("{\"kid\":\"kid-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\"}"));

    assertInstanceOf(JwtUnavailableException.class, resolveError(newResolver(), newToken("kid-1")));
  }

  @Test
  void testWrongIssuerIsRejected() {
    final var token = newToken("kid-1", keyPair, "https://other", AUDIENCE);

    final var cause = resolveError(newResolver(), token);
    assertEquals(JwtTokenException.class, cause.getClass());
  }

  @Test
  void testWrongAudienceIsRejected() {
    final var token = newToken("kid-1", keyPair, ISSUER, "other");

    final var cause = resolveError(newResolver(), token);
    assertEquals(JwtTokenException.class, cause.getClass());
  }

  private Auth0JwtTokenResolver newResolver() {
    return newResolver(Duration.ofSeconds(10));
  }

  private Auth0JwtTokenResolver newResolver(Duration minRefreshInterval) {
    return Auth0JwtTokenResolver.builder()
        .keyProvider(
            JwksKeyProvider.builder()
                .jwksUri("http://localhost:" + server.getAddress().getPort() + "/jwks")
                .connectTimeout(Duration.ofSeconds(1))
                .requestTimeout(Duration.ofSeconds(1))
                .minRefreshInterval(minRefreshInterval)
                .build())
        .issuer(ISSUER)
        .audience(AUDIENCE)
        .build();
  }

  private static Throwable resolveError(Auth0JwtTokenResolver resolver, String token) {
    final var ex =
        assertThrows(
            ExecutionException.class, () -> resolver.resolveToken(token).get(3, TimeUnit.SECONDS));
    return ex.getCause();
  }

  private String newToken(String kid) {
    return newToken(kid, keyPair, ISSUER, AUDIENCE);
  }

  private static String newToken(String kid, KeyPair keyPair, String issuer, String audience) {
    return JWT.create()
        .withKeyId(kid)
        .withIssuer(issuer)
        .withAudience(audience)
        .withClaim("role", "test")
        .sign(
            Algorithm.RSA256(
                (RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));
  }

  private static String jwks(String... keys) {
    return "{\"keys\":[" + String.join(",", keys) + "]}";
  }

  private static String rsaJwk(String kid, KeyPair keyPair) {
    final var publicKey = (RSAPublicKey) keyPair.getPublic();
    final var encoder = Base64.getUrlEncoder().withoutPadding();
    return "{\"kid\":\""
        + kid
        + "\",\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""
        + encoder.encodeToString(publicKey.getModulus().toByteArray())
        + "\",\"e\":\""
        + encoder.encodeToString(publicKey.getPublicExponent().toByteArray())
        + "\"}";
  }

  private static KeyPair newKeyPair() {
    try {
      final var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
