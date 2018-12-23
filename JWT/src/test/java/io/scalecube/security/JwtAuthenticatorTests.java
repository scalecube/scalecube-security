package io.scalecube.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class JwtAuthenticatorTests {

  private static final String HMAC_SHA_256 = "HMACSHA256";
  private final String hmacSecret = "secert";
  private KeyPair keys = generateRSAKeys();

  @Test
  public void authenticateAuthenticateUsingKidHeaderPropertyAuthenticationSuccess() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .addClaims(customClaims)
            .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256)))
            .build();

    Profile profile = sut.authenticate(token);

    assertEquals("Tenant1", profile.getTenant());
    assertEquals("Trader1", profile.getName());
    assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateCreateTokenAndAuthenticateHmacAuthenticationSuccess() {

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .addClaims(customClaims)
            .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256)))
            .build();

    Profile profile = sut.authenticate(token);

    assertEquals("Tenant1", profile.getTenant());
    assertEquals("Trader1", profile.getName());
    assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateValidTokenInvalidHmacSecretAuthenticationFailedExceptionThrown() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .addClaims(customClaims)
            .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(
                map -> Optional.of(new SecretKeySpec("otherSecret".getBytes(), HMAC_SHA_256)))
            .build();

    assertThrows(
        SignatureException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void
      authenticateAuthenticateUsingKidHeaderPropertyKidIsMissingAuthenticationFailsExceptionThrown() {

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .addClaims(customClaims)
            .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(
                map ->
                    Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(
                            s -> {
                              // Safe to cast to string, use the kid property to fetch the key
                              return Optional.of(
                                  new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256));
                            }))
            .build();
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void authenticateCreateTokenAndValidateRsaAuthenticationSuccess() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .addClaims(customClaims)
            .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(map -> Optional.of(keys.getPublic()))
            .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void
      authenticateCreateTokenAndValidateKeyResolverReturnsEmptyOptionalAuthenticationFailsExceptionThrown() {

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder().keyResolver(map -> Optional.empty()).build();
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void
      authenticateCreateTokenAndValidateWrongKeyForAlgorithmAuthenticationFailsExceptionThrown() {

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(
                map ->
                    Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(
                            s -> {
                              // Safe to cast to string, use the kid property to fetch the key
                              return Optional.of(
                                  new SecretKeySpec("secret".getBytes(), HMAC_SHA_256));
                            }))
            .build();

    assertThrows(
        UnsupportedJwtException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void authenticateHmacTokenCreatedFromDifferentLibraryAuthenticationSuccess()
      throws UnsupportedEncodingException {
    String token =
        JWT.create()
            .withAudience("Tenant1")
            .withSubject("1")
            .withKeyId("5")
            .withClaim("name", "Trader1")
            .sign(Algorithm.HMAC256(hmacSecret));

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(
                map ->
                    Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(
                            s -> {
                              // Safe to cast to string, use the kid property to fetch the key
                              return Optional.of(
                                  new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256));
                            }))
            .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateRsaTokenCreatedFromDifferentLibraryAuthenticationSuccess() {

    String token =
        JWT.create()
            .withAudience("Tenant1")
            .withSubject("1")
            .withKeyId("5")
            .withClaim("name", "Trader1")
            .sign(
                Algorithm.RSA256(
                    (RSAPublicKey) keys.getPublic(), (RSAPrivateKey) keys.getPrivate()));

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(
                map ->
                    Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(
                            s -> {
                              // Safe to cast to string, use the kid property to fetch the key
                              return Optional.of(keys.getPublic());
                            }))
            .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateMissingClaimsInTokenAuthenticationSuccessProfilePropertyIsMissing() {

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(map -> Optional.of(keys.getPublic()))
            .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals(null, profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateUnsignedTokenAuthenticationFailsExceptionThrown() {
    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(
                map ->
                    Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(
                            s -> {
                              // Safe to cast to string, use the kid property to fetch the key
                              return Optional.empty();
                            }))
            .build();

    assertThrows(
        UnsupportedJwtException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void authenticateKeyResolverRetrunNullsAuthenticationFailsExceptionThrown() {
    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder().keyResolver(map -> Optional.ofNullable(null)).build();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void authenticateNoKeyResolverIsProvidedAuthenticationFailsExceptionThrown() {

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
            .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl.Builder().build();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
  }

  @Test
  public void authenticateAuthenticateExpiredTokenFails() {

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token =
        Jwts.builder()
            .setAudience("Tenant1")
            .setSubject("1")
            .setHeaderParam("kid", "5")
            .setExpiration(Date.from(Instant.ofEpochMilli(0)))
            .addClaims(customClaims)
            .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
            .compact();

    JwtAuthenticator sut =
        new JwtAuthenticatorImpl.Builder()
            .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256)))
            .build();
    assertThrows(
        ExpiredJwtException.class,
        () -> {
          throw assertThrows(AuthenticationException.class, () -> sut.authenticate(token))
              .getCause();
        });
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
