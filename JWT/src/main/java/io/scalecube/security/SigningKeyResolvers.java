package io.scalecube.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SigningKeyResolvers {

    //TODO: extract to utility
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

    public static SigningKeyResolver defaultSigningKeyResolver(Optional<JWTKeyResolver> keyResolver) {

        return new SigningKeyResolver() {

            private Key retreiveKey(JwsHeader header, Claims claims) {

                // No key resolver provided, return null to signal no key
                if (!keyResolver.isPresent()) {
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
        };
    }
}
