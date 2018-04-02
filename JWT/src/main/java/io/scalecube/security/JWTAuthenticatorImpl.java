package io.scalecube.security;

import io.jsonwebtoken.*;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JWTAuthenticatorImpl implements JWTAuthenticator {

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

    public Profile authenticate(String token) {
        Jws<Claims> claims = Jwts.parser().setSigningKeyResolver(new SigningKeyResolver() {

            private Key retreiveKey(JwsHeader header, Claims claims) {

                // No key resolver provided, proceed without a key
                if(!keyResolver.isPresent()){
                    return null;
                }

                SignatureAlgorithm algorithm = SignatureAlgorithm.forName(header.getAlgorithm());
                JWTKeyResolver actualResolver = keyResolver.get();

                Map<String, Object> allClaims = Stream.of(claims, (Map<String, Object>) header)
                        .map(Map::entrySet)
                        .flatMap(Collection::stream)
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                Optional<byte[]> keyBytes = actualResolver.resolve(allClaims);

                if (!keyBytes.isPresent()) {
                    return null;
                }

                //TODO: should algo be provided from builder or just inferred from token?
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
                throw new UnsupportedOperationException(); // Will only occur in case the token isn't json.
            }
        }).parseClaimsJws(token);

        Claims claimBody = claims.getBody();

        return new Profile(claimBody.get("name", String.class), claimBody.getSubject(), claimBody.getAudience());
    }
}
