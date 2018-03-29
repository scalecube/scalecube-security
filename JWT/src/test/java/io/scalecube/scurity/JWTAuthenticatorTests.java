package io.scalecube.scurity;

import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class JWTAuthenticatorTests {


    @Test
    public void autenticate_createTokenAndAuthenticateHMAC_authenticationSuccess() {
        String hmacSecret = "secert";

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
                .compact();

        JWTKeyRepository mockRepo = Mockito.mock(JWTKeyRepository.class);
        Mockito.when(mockRepo.getKey(Mockito.anyString())).thenReturn(Optional.of(hmacSecret.getBytes()));

        JWTAuthenticatorImpl sut = new JWTAuthenticatorImpl(mockRepo);

        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getUserName());
        Assertions.assertEquals("1", profile.getUserId());
    }

    @Test
    public void autenticate_validTokenInvalidHMACSecret_authenticationFailedExceptionThrown() {
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, "secret".getBytes())
                .compact();

        JWTKeyRepository mockRepo = Mockito.mock(JWTKeyRepository.class);
        Mockito.when(mockRepo.getKey(Mockito.anyString())).thenReturn(Optional.of("othersecert".getBytes()));

        JWTAuthenticatorImpl sut = new JWTAuthenticatorImpl(mockRepo);

        Assertions.assertThrows(SignatureException.class, () -> sut.authenticate(token));
    }


    @Test
    public void autenticate_createTokenAndValidateRSA_authenticationSuccess() {
        KeyPair keys = generateRSAKeys();

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, "secret".getBytes())
                .compact();

        JWTKeyRepository mockRepo = Mockito.mock(JWTKeyRepository.class);
        Mockito.when(mockRepo.getKey(Mockito.anyString())).thenReturn(Optional.of(keys.getPublic().getEncoded()));

        JWTAuthenticatorImpl sut = new JWTAuthenticatorImpl(mockRepo);
        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getUserName());
        Assertions.assertEquals("1", profile.getUserId());
    }

    @Test
    public void autenticate_createTokenAndValidateEC_authenticationSuccess() {
        //TODO
//        KeyPair keys = generateECKeys();
//
//        Map<String, Object> customClaims = new HashMap<>();
//        customClaims.put("name", "Trader1");
//
//        String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
//                .setHeaderParam("kid", 1)
//                .addClaims(customClaims).signWith(SignatureAlgorithm.ES256, keys.getPrivate()).compact();
//
//        JWTKeyRepository mockRepo = Mockito.mock(JWTKeyRepository.class);
//        Mockito.when(mockRepo.getKey(Mockito.anyString())).thenReturn(keys.getPublic().getEncoded());
//
//        JWTAuthenticatorImpl sut = new JWTAuthenticatorImpl(mockRepo);
//        Profile profile = sut.authenticate(token);
//
//        Assertions.assertEquals("Tenant1", profile.getTenant());
//        Assertions.assertEquals("Trader1", profile.getUserName());
//        Assertions.assertEquals("1", profile.getUserId());
    }


    @Test
    public void autenticate_createTokenAndValidateKeyNotFoundInRepository_authenticationFailsExceptionThrown() {
        KeyPair keys = generateRSAKeys();

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
                .compact();

        JWTKeyRepository mockRepo = Mockito.mock(JWTKeyRepository.class);
        Mockito.when(mockRepo.getKey(Mockito.matches("1"))).thenReturn(Optional.of(keys.getPublic().getEncoded()));
        Mockito.when(mockRepo.getKey(Mockito.matches("5"))).thenReturn(Optional.of(keys.getPublic().getEncoded()));

        JWTAuthenticatorImpl sut = new JWTAuthenticatorImpl(mockRepo);
        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getUserName());
        Assertions.assertEquals("1", profile.getUserId());
    }

    @Test
    public void autenticate_createTokenAndValidateWrongKeyNotFound_authenticationFails() {

    }

    @Test
    public void autenticate_createTokenAndValidateWrongKeyForAlgorithm_authenticationFails() {
        //Send HMAC key to RSA Token (and vice versa)
    }

    @Test
    public void autenticate_tokenCreatedFromDifferentLibrary_authenticationSuccess() {
        // use auth.0 client library to generate the token and validate
    }

    @Test
    public void autenticate_missingClaimsInToken_authenticationSuccessProfilePropertyIsMissing() {

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
