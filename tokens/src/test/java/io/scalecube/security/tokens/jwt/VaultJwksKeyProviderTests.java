package io.scalecube.security.tokens.jwt;

import static io.scalecube.security.tokens.jwt.VaultEnvironment.createEntity;
import static io.scalecube.security.tokens.jwt.VaultEnvironment.createIdentityKey;
import static io.scalecube.security.tokens.jwt.VaultEnvironment.createIdentityRole;
import static io.scalecube.security.tokens.jwt.VaultEnvironment.createIdentityTokenPolicy;
import static io.scalecube.security.tokens.jwt.VaultEnvironment.generateIdentityToken;
import static io.scalecube.security.tokens.jwt.VaultEnvironment.jwksUri;
import static org.hamcrest.CoreMatchers.startsWith;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import java.time.Duration;
import java.util.UUID;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

class VaultJwksKeyProviderTests {

  private static final Duration TIMEOUT = Duration.ofSeconds(3);

  @BeforeEach
  void setup() {
    VaultEnvironment.start();
  }

  @AfterEach
  void cleanup() {
    VaultEnvironment.stop();
  }

  @Test
  @DisplayName("Find key successfully")
  void testFindKey() throws Exception {
    String keyName = createIdentityKey(); // oidc/key
    String roleName = createIdentityRole(keyName); // oidc/role
    createIdentityTokenPolicy(roleName); // write policy policyfile.hcl
    String clientToken = createEntity(roleName); // onboard some entity with policy line above
    String token = generateIdentityToken(clientToken, roleName); // oidc/token
    String kid = getKid(token);

    JwksKeyProvider keyProvider = new JwksKeyProvider(jwksUri());

    StepVerifier.create(keyProvider.findKey(kid))
        .expectNextCount(1)
        .expectComplete()
        .verify(TIMEOUT);
  }

  @Test
  @DisplayName("Fails to find non-existent key")
  void testFindNonExistentKey() throws Exception {
    String keyName = createIdentityKey(); // oidc/key
    String roleName = createIdentityRole(keyName); // oidc/role
    createIdentityTokenPolicy(roleName); // write policy policyfile.hcl
    String clientToken = createEntity(roleName); // onboard some entity with policy line above
    generateIdentityToken(clientToken, roleName); // oidc/token

    JwksKeyProvider keyProvider = new JwksKeyProvider(jwksUri());

    StepVerifier.create(keyProvider.findKey(UUID.randomUUID().toString()))
        .expectErrorSatisfies(
            throwable -> {
              Assertions.assertEquals(throwable.getClass(), KeyProviderException.class);
              MatcherAssert.assertThat(throwable.getMessage(), startsWith("Key was not found"));
            })
        .verify(TIMEOUT);
  }

  @Test
  @DisplayName("Fails to find key on empty environment")
  void testKeyNotFoundOnEmptyEnvironment() {
    JwksKeyProvider keyProvider = new JwksKeyProvider(jwksUri());

    StepVerifier.create(keyProvider.findKey(UUID.randomUUID().toString()))
        .expectErrorSatisfies(
            throwable -> {
              Assertions.assertEquals(throwable.getClass(), KeyProviderException.class);
              MatcherAssert.assertThat(throwable.getMessage(), startsWith("Key was not found"));
            })
        .verify(TIMEOUT);
  }

  private static String getKid(String token) {
    String justClaims = token.substring(0, token.lastIndexOf(".") + 1);
    JwtParserBuilder parserBuilder = Jwts.parserBuilder();
    //noinspection rawtypes
    Jwt<Header, Claims> claims = parserBuilder.build().parseClaimsJwt(justClaims);
    //noinspection rawtypes
    Header header = claims.getHeader();
    return (String) header.get("kid");
  }
}
