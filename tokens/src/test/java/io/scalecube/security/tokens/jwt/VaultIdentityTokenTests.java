package io.scalecube.security.tokens.jwt;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.Locator;
import java.security.Key;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class VaultIdentityTokenTests {

  private static final Duration TIMEOUT = Duration.ofSeconds(3);

  private static VaultEnvironment vaultEnvironment;

  @BeforeAll
  static void beforeAll() {
    vaultEnvironment = VaultEnvironment.start();
  }

  @AfterAll
  static void afterAll() {
    if (vaultEnvironment != null) {
      vaultEnvironment.close();
    }
  }

  @Test
  void testResolveTokenSuccessfully() throws Exception {
    final var token = generateToken();

    final var jwtToken =
        new JsonwebtokenResolver(
                new JwksKeyLocator.Builder()
                    .jwksUri(vaultEnvironment.jwksUri())
                    .connectTimeout(Duration.ofSeconds(3))
                    .requestTimeout(Duration.ofSeconds(3))
                    .keyTtl(1000)
                    .build())
            .resolve(token)
            .block(TIMEOUT);

    assertNotNull(jwtToken, "jwtToken");
    assertTrue(jwtToken.header().size() > 0, "jwtToken.header: " + jwtToken.header());
    assertTrue(jwtToken.payload().size() > 0, "jwtToken.payload: " + jwtToken.payload());
  }

  @Test
  void testJwksKeyLocatorThrowsError() throws Exception {
    final var token = generateToken();

    Locator<Key> keyLocator = mock(Locator.class);
    when(keyLocator.locate(any())).thenThrow(new RuntimeException("Cannot get key"));

    try {
      new JsonwebtokenResolver(keyLocator).resolve(token).block(TIMEOUT);
      fail("Expected exception");
    } catch (Exception ex) {
      assertNotNull(ex.getMessage());
      assertTrue(ex.getMessage().startsWith("Cannot get key"));
    }
  }

  private static String generateToken() throws Exception {
    String keyName = vaultEnvironment.createIdentityKey(); // oidc/key
    String roleName = vaultEnvironment.createIdentityRole(keyName); // oidc/role
    vaultEnvironment.createIdentityTokenPolicy(roleName); // policy policyfile.hcl
    String clientToken = vaultEnvironment.createEntity(roleName); // onboard entity with policy
    return vaultEnvironment.generateIdentityToken(clientToken, roleName);
  }
}
