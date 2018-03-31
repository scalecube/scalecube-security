package io.scalecube.scurity;

import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.swing.text.html.Option;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

public class JWTAuthenticatorTests {

    @Test
    public void autenticate_autenticateUsingKidHeaderProperty_authenticationSuccess() {
        String hmacSecret = "secert";

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
                .compact();


        JWTAuthenticator sut = new JWTAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(s -> {
                             //Safe to cast to string, use the kid property to fetch the key
                             return Optional.of(hmacSecret.getBytes());
                         }))
                .build();

        Profile profile = sut.authenticate(token);

        Assertions.assertEquals("Tenant1", profile.getTenant());
        Assertions.assertEquals("Trader1", profile.getUserName());
        Assertions.assertEquals("1", profile.getUserId());

    }

    @Test
    public void autenticate_createTokenAndAuthenticateHMAC_authenticationSuccess() {
        String hmacSecret = "secert";

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
                .compact();


        JWTAuthenticator sut = new JWTAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.of(hmacSecret.getBytes()))
                .build();

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

        JWTAuthenticator sut = new JWTAuthenticatorImpl.Builder()
                .keyResolver(map -> Optional.of("otherSecret".getBytes()))
                .build();

        Assertions.assertThrows(SignatureException.class, () -> sut.authenticate(token));
    }


    @Test
    public void autenticate_autenticateUsingKidHeaderPropertyKidIsMissing_authenticationFailsExceptionThrown() {
        String hmacSecret = "secert";

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
                .compact();


        JWTAuthenticator sut = new JWTAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.ofNullable(map.get("kid"))
                        .filter(String.class::isInstance)
                        .flatMap(s -> {
                            //Safe to cast to string, use the kid property to fetch the key
                            return Optional.of(hmacSecret.getBytes());
                        }))
                .build();

        Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));


    }

    @Test
    public void autenticate_createTokenAndValidateRSA_authenticationSuccess() {
        KeyPair keys = generateRSAKeys();

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("name", "Trader1");

        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .addClaims(customClaims)
                .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
                .compact();

        JWTAuthenticator sut = new JWTAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.of(keys.getPublic().getEncoded()))
                .build();

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
    public void autenticate_createTokenAndValidateKeyResolverReturnsEmptyOptional_authenticationFailsExceptionThrown() {
        KeyPair keys = generateRSAKeys();


        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
                .signWith(SignatureAlgorithm.RS256, keys.getPrivate())
                .compact();

        JWTAuthenticator sut = new JWTAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.empty())
                .build();

        Assertions.assertThrows(Exception.class, () -> sut.authenticate(token));
    }


    @Test
    public void autenticate_createTokenAndValidateWrongKeyForAlgorithm_authenticationFails() {
        //TODO: Send HMAC key to RSA Token (and vice versa)
    }

    @Test
    public void autenticate_tokenCreatedFromDifferentLibrary_authenticationSuccess() {
        //TODO: use auth.0 client library to generate the token and validate
    }

    @Test
    public void autenticate_missingClaimsInToken_authenticationSuccessProfilePropertyIsMissing() {
        //TODO: missing profile property in token claim
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
//TODO: remove
//    @Test
//    public void autenticate_customKeyResolver_success() {
//
//        String hmacSecret = "secert";
//
//        Map<String, Object> customClaims = new HashMap<>();
//        customClaims.put("name", "Trader1");
//
//        String token = Jwts.builder().setAudience("Tenant1").setSubject("1").setHeaderParam("kid", "5")
//                .addClaims(customClaims)
//                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
//                .compact();
//
//
//        JWTAuthenticatorImpl sut = new JWTAuthenticatorImpl();
//
//        Profile profile = sut.authenticate(token, tokenClaims -> {
//
//            String keyId =  tokenClaims.get("kid").toString();
//
//            // e.g. fetch key using provided key id from external repository
//            return Optional.of(hmacSecret.getBytes());
//        });
//
//        Assertions.assertEquals("Tenant1", profile.getTenant());
//        Assertions.assertEquals("Trader1", profile.getUserName());
//        Assertions.assertEquals("1", profile.getUserId());
//
//
//    }

}
