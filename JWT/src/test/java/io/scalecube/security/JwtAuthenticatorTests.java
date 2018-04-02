package io.scalecube.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class JwtAuthenticatorTests {

    @Test
    void authenticate_authenticateUsingKidHeaderProperty_authenticationSuccess() {
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
                .keyResolver(map -> Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(s -> {
                            //Safe to cast to string, use the kid property to fetch the key
                            return Optional.of(new SecretKeySpec(hmacSecret.getBytes(), "HMACSHA256"));
                        }))
                .build();

        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getName());
        Assertions.assertEquals("1", profile.getUserId());
    }

    @Test
    void authenticate_createTokenAndAuthenticateHMAC_authenticationSuccess() {
        String hmacSecret = "secert";

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
                .compact();


        JwtAuthenticator sut = new JwtAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), "HMACSHA256")))
                .build();

        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getName());
        Assertions.assertEquals("1", profile.getUserId());
    }

    @Test
    void authenticate_validTokenInvalidHMACSecret_authenticationFailedExceptionThrown() {
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, "secret".getBytes())
                .compact();

        JwtAuthenticator sut = new JwtAuthenticatorImpl.Builder()
                .keyResolver(map -> Optional.of(new SecretKeySpec("otherSecret".getBytes(), "HMACSHA256")))
                .build();

        Assertions.assertThrows(SignatureException.class, () -> sut.authenticate(token));
    }

    @Test
    void authenticate_authenticateUsingKidHeaderPropertyKidIsMissing_authenticationFailsExceptionThrown() {
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
                            return Optional.of(new SecretKeySpec(hmacSecret.getBytes(), "HMACSHA256"));
                        }))
                .build();

        Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
    }

    @Test
    void authenticate_createTokenAndValidateRSA_authenticationSuccess() {
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
    void authenticate_createTokenAndValidateEC_authenticationSuccess() {
        //TODO
    }

    @Test
    void authenticate_createTokenAndValidateKeyResolverReturnsEmptyOptional_authenticationFailsExceptionThrown() {
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
    void authenticate_createTokenAndValidateWrongKeyForAlgorithm_authenticationFailsExceptionThrown() {
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
                            return Optional.of(new SecretKeySpec("secret".getBytes(), "HMACSHA256"));
                        }))
                .build();

        Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
    }

    @Test
    void authenticate_hmacTokenCreatedFromDifferentLibrary_authenticationSuccess() {

        String hmacSecret = "secret";
        String token;
        try {
            token = JWT.create()
                    .withAudience("Tenant1")
                    .withSubject("1")
                    .withKeyId("5")
                    .withClaim("name", "Trader1")
                    .sign(Algorithm.HMAC256(hmacSecret));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        JwtAuthenticator sut = new JwtAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(s -> {
                            //Safe to cast to string, use the kid property to fetch the key
                            return Optional.of(new SecretKeySpec(hmacSecret.getBytes(), "HMACSHA256"));

                        }))
                .build();

        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getName());
        Assertions.assertEquals("1", profile.getUserId());
    }

    @Test
    void authenticate_RSATokenCreatedFromDifferentLibrary_authenticationSuccess() {

        KeyPair keyPair = generateRSAKeys();
        String token;
        try {
            token = JWT.create()
                    .withAudience("Tenant1")
                    .withSubject("1")
                    .withKeyId("5")
                    .withClaim("name", "Trader1")
                    .sign(Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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
    void authenticate_missingClaimsInToken_authenticationSuccessProfilePropertyIsMissing() {
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
    void authenticate_unsignedToken_authenticationFailsExceptionThrown() {

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
    void authenticate_keyResolverRetrunNulls_authenticationFailsExceptionThrown() {

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

    private KeyPair generateRSAKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private KeyPair generateECKeys() {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime192v1");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecGenSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

    }
}
