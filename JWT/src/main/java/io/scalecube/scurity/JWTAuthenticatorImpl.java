package io.scalecube.scurity;

import io.jsonwebtoken.*;

import javax.crypto.spec.SecretKeySpec;
import javax.swing.text.html.Option;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JWTAuthenticatorImpl implements JWTAuthenticator {

    //TODO: lazy installation of the key factory?
    private static final Map<String, Supplier<KeyFactory>> keyFactorySupplier;

    static {
        keyFactorySupplier = new HashMap<>();
        keyFactorySupplier.put("RSA", () -> {
            try {
                return KeyFactory.getInstance("RSA");

            } catch (NoSuchAlgorithmException ignored) {
                ignored.printStackTrace();
                return null;
            }
        });
        keyFactorySupplier.put("Elliptic Curve", () -> {
            try {
                return KeyFactory.getInstance("EC");

            } catch (NoSuchAlgorithmException ignored) {
                ignored.printStackTrace();
                return null;
            }
        });
    }

    Optional<JWTKeyResolver> keyResolver;

    public static class Builder {

        Optional<JWTKeyResolver> keyResolver = Optional.empty();

        public Builder keyResolver(JWTKeyResolver keyResolver) {
            this.keyResolver = Optional.of(keyResolver);
            return this;
        }

        public JWTAuthenticator build() {
            return new JWTAuthenticatorImpl(keyResolver);
        }
    }

    private JWTAuthenticatorImpl(Optional<JWTKeyResolver> keyResolver) {
        this.keyResolver = keyResolver;
    }

    // TODO: can i improve this ugly anonymous class impl?
    public Profile authenticate(String token) {
        Jws<Claims> claims = Jwts.parser().setSigningKeyResolver(new SigningKeyResolver() {

            private Key retreiveKey(JwsHeader header, Claims claims) {

                // No key resolver provided, proceed without a key
                if(!keyResolver.isPresent()){
                    return null;
                }

                SignatureAlgorithm algorithm = SignatureAlgorithm.forName(header.getAlgorithm());
                JWTKeyResolver actualResolver = keyResolver.get(); //TODO: return default resolver if not exists

                Map<String, Object> allClaims = Stream.of(claims, (Map<String, Object>) header)
                        .map(Map::entrySet)
                        .flatMap(Collection::stream)
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                Optional<byte[]> keyBytes = actualResolver.resolve(allClaims);

                if (!keyBytes.isPresent()) {
                    return null;
                }

                //TODO: provide ability to provide algorithm in builder, fall back to retrieving from token iself?
                if (algorithm.isHmac()) {
                    return new SecretKeySpec(keyBytes.get(), algorithm.getJcaName());
                }
                if (algorithm.isRsa() || algorithm.isEllipticCurve()) {
                    try {
                        return keyFactorySupplier.get(algorithm.getFamilyName()).get()
                                .generatePublic(new X509EncodedKeySpec(keyBytes.get()));
                    } catch (InvalidKeySpecException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                throw new UnsupportedOperationException("signature algorithm: " + algorithm.getFamilyName() + " currently unsupported");
            }

            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                return retreiveKey(header, claims);
            }

            @Override
            public Key resolveSigningKey(JwsHeader header, String plaintext) {
                throw new UnsupportedOperationException(); //TODO: check how to support this method?
            }
        }).parseClaimsJws(token);

        Claims claimBody = claims.getBody();

        return new Profile(claimBody.get("name", String.class), claimBody.getSubject(), claimBody.getAudience());
    }
}
