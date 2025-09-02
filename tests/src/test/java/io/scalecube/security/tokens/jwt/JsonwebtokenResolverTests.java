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
import io.scalecube.security.environment.IntegrationEnvironmentFixture;
import io.scalecube.security.environment.VaultEnvironment;
import java.security.Key;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(IntegrationEnvironmentFixture.class)
public class JsonwebtokenResolverTests {

  @Test
  void testResolveTokenTokenSuccessfully(VaultEnvironment vaultEnvironment) throws Exception {
    final var token = vaultEnvironment.newServiceToken();

    final var jwtToken =
        new JsonwebtokenResolver(
                JwksKeyLocator.builder()
                    .jwksUri(vaultEnvironment.jwksUri())
                    .connectTimeout(Duration.ofSeconds(3))
                    .requestTimeout(Duration.ofSeconds(3))
                    .keyTtl(1000)
                    .build())
            .resolveToken(token)
            .get(3, TimeUnit.SECONDS);

    assertNotNull(jwtToken, "jwtToken");
    assertTrue(jwtToken.header().size() > 0, "jwtToken.header: " + jwtToken.header());
    assertTrue(jwtToken.payload().size() > 0, "jwtToken.payload: " + jwtToken.payload());
  }

  @Test
  void testParseTokenSuccessfully(VaultEnvironment vaultEnvironment) {
    final var token = vaultEnvironment.newServiceToken();

    final var jwtToken = JwtToken.parseToken(token);

    assertNotNull(jwtToken, "jwtToken");
    assertTrue(jwtToken.header().size() > 0, "jwtToken.header: " + jwtToken.header());
    assertTrue(jwtToken.payload().size() > 0, "jwtToken.payload: " + jwtToken.payload());
  }

  @Test
  void testJwksKeyLocatorThrowsError(VaultEnvironment vaultEnvironment) {
    final var token = vaultEnvironment.newServiceToken();

    Locator<Key> keyLocator = mock(Locator.class);
    when(keyLocator.locate(any())).thenThrow(new RuntimeException("Cannot get key"));

    try {
      new JsonwebtokenResolver(keyLocator).resolveToken(token).get(3, TimeUnit.SECONDS);
      fail("Expected exception");
    } catch (Exception e) {
      final var ex = getRootCause(e);
      assertThat(ex, instanceOf(RuntimeException.class));
      assertThat(ex.getMessage(), startsWith("Cannot get key"));
    }
  }

  @Test
  void testJwksKeyLocatorThrowsRetryableError(VaultEnvironment vaultEnvironment) {
    final var token = vaultEnvironment.newServiceToken();

    Locator<Key> keyLocator = mock(Locator.class);
    when(keyLocator.locate(any())).thenThrow(new JwtUnavailableException("JWKS timeout"));

    try {
      new JsonwebtokenResolver(keyLocator).resolveToken(token).get(3, TimeUnit.SECONDS);
      fail("Expected exception");
    } catch (Exception e) {
      final var ex = getRootCause(e);
      assertThat(ex, instanceOf(JwtUnavailableException.class));
      assertThat(ex.getMessage(), startsWith("JWKS timeout"));
    }
  }
}
