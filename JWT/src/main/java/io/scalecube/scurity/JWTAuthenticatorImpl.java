package io.scalecube.scurity;

import io.jsonwebtoken.*;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

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

    private final JWTKeyRepository jwtKeyRepository;

    public JWTAuthenticatorImpl(JWTKeyRepository keyRepository) {

        this.jwtKeyRepository = Objects.requireNonNull(keyRepository);
    }

    // Create key resolver (lambda) - create default implementation
    // builder to set Algo (Strategy pattern) type and resolver.
    public Profile authenticate(String token) {
        Jws<Claims> claims = Jwts.parser().setSigningKeyResolver(new SigningKeyResolver() {

            private Key retreiveKey(JwsHeader header) {
                SignatureAlgorithm algorithm = SignatureAlgorithm.forName(header.getAlgorithm());
                byte[] keyBytes = jwtKeyRepository.getKey(header.getKeyId()).get(); //TODO: change

                if (algorithm.isHmac()) {
                    return new SecretKeySpec(keyBytes, algorithm.getJcaName());
                }
                if (algorithm.isRsa() || algorithm.isEllipticCurve()) {
                    try {
                        return keyFactorySupplier.get(algorithm.getFamilyName()).get()
                                .generatePublic(new X509EncodedKeySpec(keyBytes));
                    } catch (InvalidKeySpecException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                throw new UnsupportedOperationException("signature algorithm: " + algorithm.getFamilyName() + " currently unsupported");
            }

            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                return retreiveKey(header);
            }

            @Override
            public Key resolveSigningKey(JwsHeader header, String plaintext) {
                return retreiveKey(header);
            }
        }).parseClaimsJws(token);

        Claims claimBody = claims.getBody();

        return new Profile(claimBody.get("name", String.class), claimBody.getSubject(), claimBody.getAudience());
    }
}
