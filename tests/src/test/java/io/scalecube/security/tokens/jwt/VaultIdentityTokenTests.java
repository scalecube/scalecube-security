package io.scalecube.security.tokens.jwt;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.Locator;
import io.scalecube.security.environment.VaultEnvironment;
import java.security.Key;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class VaultIdentityTokenTests {

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
            .get(3, TimeUnit.SECONDS);

    assertNotNull(jwtToken, "jwtToken");
    Assertions.assertTrue(jwtToken.header().size() > 0, "jwtToken.header: " + jwtToken.header());
    Assertions.assertTrue(jwtToken.payload().size() > 0, "jwtToken.payload: " + jwtToken.payload());
  }

  @Test
  void testJwksKeyLocatorThrowsError() throws Exception {
    final var token = generateToken();

    Locator<Key> keyLocator = mock(Locator.class);
    when(keyLocator.locate(any())).thenThrow(new RuntimeException("Cannot get key"));

    try {
      new JsonwebtokenResolver(keyLocator).resolve(token).get(3, TimeUnit.SECONDS);
      fail("Expected exception");
    } catch (ExecutionException e) {
      final var ex = e.getCause();
      assertNotNull(ex);
      assertNotNull(ex.getMessage());
      assertTrue(ex.getMessage().startsWith("Cannot get key"));
    }
  }

  private static String generateToken() {
    String keyName = vaultEnvironment.createIdentityKey(); // oidc/key
    String roleName = vaultEnvironment.createIdentityRole(keyName); // oidc/role
    String clientToken = vaultEnvironment.login(); // onboard entity with policy
    return vaultEnvironment.generateIdentityToken(clientToken, roleName);
  }
}
