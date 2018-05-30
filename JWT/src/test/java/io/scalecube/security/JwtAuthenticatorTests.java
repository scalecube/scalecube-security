package io.scalecube.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class JwtAuthenticatorTests {

  private static final String HMAC_SHA_256 = "HMACSHA256";

  @Test
  public void authenticateAuthenticateUsingKidHeaderPropertyAuthenticationSuccess() {
    String hmacSecret = "secert";

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token = Jwts.builder().setAudience("Tenant1")
        .setSubject("1")
        .setHeaderParam("kid", "5")
        .addClaims(customClaims)
        .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256)))
        .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateCreateTokenAndAuthenticateHmacAuthenticationSuccess() {
    String hmacSecret = "secert";

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
        .addClaims(customClaims)
        .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
        .compact();


    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256)))
        .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateValidTokenInvalidHmacSecretAuthenticationFailedExceptionThrown() {
    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "trader1");

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
        .addClaims(customClaims)
        .signWith(SignatureAlgorithm.HS256, "secret".getBytes())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl.Builder()
        .keyResolver(map -> Optional.of(new SecretKeySpec("otherSecret".getBytes(), HMAC_SHA_256)))
        .build();

    Assertions.assertThrows(SignatureException.class, () -> sut.authenticate(token));
  }

  @Test
  public void authenticateAuthenticateUsingKidHeaderPropertyKidIsMissingAuthenticationFailsExceptionThrown() {
    String hmacSecret = "secert";

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
        .addClaims(customClaims)
        .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
        .compact();


    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.ofNullable(map.get("kid"))
            .filter(String.class::isInstance)
            .flatMap(s -> {
              //Safe to cast to string, use the kid property to fetch the key
              return Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256));
            }))
        .build();

    Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
  }

  @Test
  public void authenticateCreateTokenAndValidateRsaAuthenticationSuccess() throws NoSuchAlgorithmException {
    KeyPair keys = generateRSAKeys();

    Map<String, Object> customClaims = new HashMap<>();
    customClaims.put("name", "Trader1");

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
        .addClaims(customClaims)
        .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.of(keys.getPublic()))
        .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateCreateTokenAndValidateKeyResolverReturnsEmptyOptionalAuthenticationFailsExceptionThrown() throws NoSuchAlgorithmException {
    KeyPair keys = generateRSAKeys();

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
        .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.empty())
        .build();

    Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
  }

  @Test
  public void authenticateCreateTokenAndValidateWrongKeyForAlgorithmAuthenticationFailsExceptionThrown() throws NoSuchAlgorithmException {
    KeyPair keys = generateRSAKeys();

    String token = Jwts.builder().setAudience("Tenant1")
        .setSubject("1")
        .setHeaderParam("kid", "5")
        .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.ofNullable(map.get("kid"))
            .filter(String.class::isInstance)
            .flatMap(s -> {
              //Safe to cast to string, use the kid property to fetch the key
              return Optional.of(new SecretKeySpec("secret".getBytes(), HMAC_SHA_256));
            }))
        .build();

    Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
  }

  @Test
  public void authenticateHmacTokenCreatedFromDifferentLibraryAuthenticationSuccess() throws UnsupportedEncodingException {

    String hmacSecret = "secret";
    String token;

      token = JWT.create()
          .withAudience("Tenant1")
          .withSubject("1")
          .withKeyId("5")
          .withClaim("name", "Trader1")
          .sign(Algorithm.HMAC256(hmacSecret));

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.ofNullable(map.get("kid"))
            .filter(String.class::isInstance)
            .flatMap(s -> {
              //Safe to cast to string, use the kid property to fetch the key
              return Optional.of(new SecretKeySpec(hmacSecret.getBytes(), HMAC_SHA_256));

            }))
        .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateRsaTokenCreatedFromDifferentLibraryAuthenticationSuccess() throws NoSuchAlgorithmException {

    KeyPair keyPair = generateRSAKeys();
    String token;
      token = JWT.create()
          .withAudience("Tenant1")
          .withSubject("1")
          .withKeyId("5")
          .withClaim("name", "Trader1")
          .sign(Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.ofNullable(map.get("kid"))
            .filter(String.class::isInstance)
            .flatMap(s -> {
              //Safe to cast to string, use the kid property to fetch the key
              return Optional.of(keyPair.getPublic());
            }))
        .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals("Trader1", profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateMissingClaimsInTokenAuthenticationSuccessProfilePropertyIsMissing() throws NoSuchAlgorithmException {
    KeyPair keys = generateRSAKeys();

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
        .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.of(keys.getPublic()))
        .build();

    Profile profile = sut.authenticate(token);

    Assertions.assertEquals("Tenant1", profile.getTenant());
    Assertions.assertEquals(null, profile.getName());
    Assertions.assertEquals("1", profile.getUserId());
  }

  @Test
  public void authenticateUnsignedTokenAauthenticationFailsExceptionThrown() {

    String token = Jwts.builder().setAudience("Tenant1")
        .setSubject("1")
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.ofNullable(map.get("kid"))
            .filter(String.class::isInstance)
            .flatMap(s -> {
              //Safe to cast to string, use the kid property to fetch the key
              return Optional.ofNullable(null);
            }))
        .build();

    Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
  }

  @Test
  public void authenticateKeyResolverRetrunNullsAuthenticationFailsExceptionThrown() throws NoSuchAlgorithmException {

    KeyPair keys = generateRSAKeys();

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
        .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .keyResolver(map -> Optional.ofNullable(null))
        .build();

    Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
  }

  @Test
  void authenticate_noKeyResolverIsProvided_authenticationFailsExceptionThrown() throws NoSuchAlgorithmException {
    KeyPair keys = generateRSAKeys();

    String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
        .setHeaderParam("kid", "5")
        .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
        .compact();

    JwtAuthenticator sut = new JwtAuthenticatorImpl
        .Builder()
        .build();

    Assertions.assertThrows(IllegalArgumentException.class, () -> sut.authenticate(token));
  }

  private KeyPair generateRSAKeys() throws NoSuchAlgorithmException {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      return kpg.generateKeyPair();
  }
}
