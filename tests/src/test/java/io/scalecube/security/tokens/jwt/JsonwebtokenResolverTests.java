package io.scalecube.security.tokens.jwt;

import static io.scalecube.security.environment.VaultEnvironment.getRootCause;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringStartsWith.startsWith;
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
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class JsonwebtokenResolverTests {

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
    assertTrue(jwtToken.header().size() > 0, "jwtToken.header: " + jwtToken.header());
    assertTrue(jwtToken.payload().size() > 0, "jwtToken.payload: " + jwtToken.payload());
  }

  @Test
  void testJwksKeyLocatorThrowsError() {
    final var token = generateToken();

    Locator<Key> keyLocator = mock(Locator.class);
    when(keyLocator.locate(any())).thenThrow(new RuntimeException("Cannot get key"));

    try {
      new JsonwebtokenResolver(keyLocator).resolve(token).get(3, TimeUnit.SECONDS);
      fail("Expected exception");
    } catch (Exception e) {
      final var ex = getRootCause(e);
      assertThat(ex, instanceOf(RuntimeException.class));
      assertThat(ex.getMessage(), startsWith("Cannot get key"));
    }
  }

  @Test
  void testJwksKeyLocatorThrowsRetryableError() {
    final var token = generateToken();

    Locator<Key> keyLocator = mock(Locator.class);
    when(keyLocator.locate(any())).thenThrow(new JwtUnavailableException("JWKS timeout"));

    try {
      new JsonwebtokenResolver(keyLocator).resolve(token).get(3, TimeUnit.SECONDS);
      fail("Expected exception");
    } catch (Exception e) {
      final var ex = getRootCause(e);
      assertThat(ex, instanceOf(JwtUnavailableException.class));
      assertThat(ex.getMessage(), startsWith("JWKS timeout"));
    }
  }

  private static String generateToken() {
    String keyName = vaultEnvironment.createIdentityKey(); // oidc/key
    String roleName = vaultEnvironment.createIdentityRole(keyName); // oidc/role
    String clientToken = vaultEnvironment.login(); // onboard entity with policy
    return vaultEnvironment.generateIdentityToken(clientToken, roleName);
  }
}
