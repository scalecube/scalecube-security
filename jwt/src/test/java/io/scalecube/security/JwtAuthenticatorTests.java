package io.scalecube.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class JwtAuthenticatorTests {

  private static final Key hmacSecretKey =
      new SecretKeySpec(
          UUID.randomUUID().toString().getBytes(), SignatureAlgorithm.HS256.getJcaName());
//  private static final Mono<Key> hmacSecretKeyMono = Mono.just(hmacSecretKey).cache();
  private static final KeyPair keys = generateRSAKeys();

  @Test
  void authenticateAuthenticateUsingKidHeaderPropertyAuthenticationSuccess() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .addClaims(customClaims)
            .signWith(hmacSecretKey)
            .compact();

    JwtAuthenticator sut = new DefaultJwtAuthenticator(map -> hmacSecretKey);

    StepVerifier.create(sut.authenticate(token))
        .assertNext(
            profile -> {
              assertEquals("Tenant1", profile.tenant());
              assertEquals("Trader1", profile.name());
              assertEquals("1", profile.userId());
            })
        .verifyComplete();
  }

  @Test
  void authenticateCreateTokenAndAuthenticateHmacAuthenticationSuccess() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .addClaims(customClaims)
            .signWith(hmacSecretKey)
            .compact();

    JwtAuthenticator sut = new DefaultJwtAuthenticator(map -> hmacSecretKey);

    StepVerifier.create(sut.authenticate(token))
    .assertNext(
        profile -> {

    assertEquals("Tenant1", profile.tenant());
    assertEquals("Trader1", profile.name());
    assertEquals("1", profile.userId());
        }).verifyComplete();
  }

  @Test
  void authenticateValidTokenInvalidHmacSecretAuthenticationFailedExceptionThrown() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .addClaims(customClaims)
            .signWith(hmacSecretKey)
            .compact();

    JwtAuthenticator sut =
        new DefaultJwtAuthenticator(
            map ->
                new SecretKeySpec(
                    UUID.randomUUID().toString().getBytes(),
                    SignatureAlgorithm.HS256.getJcaName()));

    AuthenticationException actualException =
        assertThrows(AuthenticationException.class, () -> sut.authenticate(token));
    assertEquals(SignatureException.class, actualException.getCause().getClass());
  }

  @Test
  void
      authenticateAuthenticateUsingKidHeaderPropertyKidIsMissingAuthenticationFailsExceptionThrown() {

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .addClaims(customClaims)
            .signWith(hmacSecretKey)
            .compact();

    JwtAuthenticator sut =
        new DefaultJwtAuthenticator(
            map ->
                Optional.ofNullable(map.get("kid"))
                    .filter(String.class::isInstance)
                    .map(
                        s -> {
                          // Safe to cast to string, use the kid property to fetch the key
                          return hmacSecretKey;
                        })
                    .orElse(null));

    AuthenticationException actualException =
        assertThrows(AuthenticationException.class, () -> sut.authenticate(token));
    assertEquals(IllegalArgumentException.class, actualException.getCause().getClass());
  }

  @Test
  void authenticateCreateTokenAndValidateRsaAuthenticationSuccess() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .addClaims(customClaims)
            .signWith(keys.getPrivate())
            .compact();

    JwtAuthenticator sut = new DefaultJwtAuthenticator(map -> keys.getPublic());

    StepVerifier.create(sut.authenticate(token))
    .assertNext(
        profile -> {
          assertEquals("Tenant1", profile.tenant());
          assertEquals("Trader1", profile.name());
          assertEquals("1", profile.userId());
        }).verifyComplete();
  }

  @Test
  void authenticateCreateTokenAndValidateWrongKeyForAlgorithmAuthenticationFailsExceptionThrown() {

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(keys.getPrivate())
            .compact();

    JwtAuthenticator sut =
        new DefaultJwtAuthenticator(
            map ->
                Optional.ofNullable(map.get("kid"))
                    .filter(String.class::isInstance)
                    .map(
                        s -> {
                          // Safe to cast to string, use the kid property to fetch the key
                          return hmacSecretKey;
                        })
                    .orElse(null));

    AuthenticationException actualException =
        assertThrows(AuthenticationException.class, () -> sut.authenticate(token));
    assertEquals(UnsupportedJwtException.class, actualException.getCause().getClass());
  }

  @Test
  void authenticateMissingClaimsInTokenAuthenticationSuccessProfilePropertyIsMissing() {

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(keys.getPrivate())
            .compact();

    JwtAuthenticator sut = new DefaultJwtAuthenticator(map -> keys.getPublic());

    StepVerifier.create(sut.authenticate(token))
    .assertNext(
        profile -> {
          assertEquals("Tenant1", profile.tenant());
          assertNull(profile.name());
          assertEquals("1", profile.userId());
        }).verifyComplete();
  }

  @Test
  void authenticateUnsignedTokenAuthenticationFailsExceptionThrown() {
    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").compact();

    JwtAuthenticator sut =
        new DefaultJwtAuthenticator(
            map ->
                Optional.ofNullable(map.get("kid"))
                    .filter(String.class::isInstance)
                    .map(
                        s -> {
                          // Safe to cast to string, use the kid property to fetch the key
                          return hmacSecretKey;
                        })
                    .orElse(null));

    AuthenticationException actualException =
        assertThrows(AuthenticationException.class, () -> sut.authenticate(token));
    assertEquals(UnsupportedJwtException.class, actualException.getCause().getClass());
  }

  @Test
  void authenticateKeyResolverReturnNullsAuthenticationFailsExceptionThrown() {
    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(keys.getPrivate())
            .compact();

    JwtAuthenticator sut = new DefaultJwtAuthenticator(map -> null);

    AuthenticationException actualException =
        assertThrows(AuthenticationException.class, () -> sut.authenticate(token));
    assertEquals(IllegalArgumentException.class, actualException.getCause().getClass());
  }

  @Test
  void authenticateAuthenticateExpiredTokenFails() {

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .setExpiration(Date.from(Instant.ofEpochMilli(0)))
            .addClaims(customClaims)
            .signWith(hmacSecretKey)
            .compact();

    JwtAuthenticator sut = new DefaultJwtAuthenticator(map -> hmacSecretKey);

    AuthenticationException actualException =
        assertThrows(AuthenticationException.class, () -> sut.authenticate(token));
    assertEquals(ExpiredJwtException.class, actualException.getCause().getClass());
  }

  private static KeyPair generateRSAKeys() {
    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      return kpg.generateKeyPair();
    } catch (NoSuchAlgorithmException impossibleException) {
      return Assertions.fail("This should not happen", impossibleException);
    }
  }
}
