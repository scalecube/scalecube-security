package io.scalecube.security;

import io.jsonwebtoken.*;

import java.util.*;

public class JWTAuthenticatorImpl implements JWTAuthenticator {

    Optional<JWTKeyResolver> keyResolver;

    private JWTAuthenticatorImpl(Optional<JWTKeyResolver> keyResolver) {
        this.keyResolver = keyResolver;
    }

    public Profile authenticate(String token) {

        SigningKeyResolver signingKeyResolver = SigningKeyResolvers.defaultSigningKeyResolver(keyResolver);

        Jws<Claims> claims = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);

        Claims tokenClaims = claims.getBody();

        return new Profile(tokenClaims.get("sub",String.class), tokenClaims.get("aud",String.class),
                tokenClaims.get("email",String.class),tokenClaims.get("email_verified",Boolean.class),
                tokenClaims.get("name",String.class),tokenClaims.get("family_name",String.class),
                tokenClaims.get("given_name",String.class),tokenClaims);
    }

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
}