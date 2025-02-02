package io.scalecube.security.vault;

import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.testcontainers.shaded.org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;

import io.scalecube.security.environment.VaultEnvironment;
import io.scalecube.security.tokens.jwt.JsonwebtokenResolver;
import io.scalecube.security.tokens.jwt.JwksKeyLocator;
import io.scalecube.security.vault.VaultServiceRolesInstaller.ServiceRoles;
import io.scalecube.security.vault.VaultServiceRolesInstaller.ServiceRoles.Role;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class VaultServiceTokenTests {

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
  void testGetServiceTokenUsingWrongCredentials() throws Exception {
    final var serviceTokenSupplier =
        new VaultServiceTokenSupplier.Builder()
            .vaultAddress(vaultEnvironment.vaultAddr())
            .vaultTokenSupplier(() -> completedFuture(randomAlphabetic(16)))
            .serviceRole(randomAlphabetic(16))
            .serviceTokenNameBuilder((role, attributes) -> role)
            .build();

    try {
      serviceTokenSupplier.getToken(Collections.emptyMap()).get(3, TimeUnit.SECONDS);
      fail("Exception expected");
    } catch (ExecutionException e) {
      final var ex = e.getCause();
      assertNotNull(ex);
      assertNotNull(ex.getMessage());
      assertTrue(
          ex.getMessage().contains("Failed to get service token, status=403"), "Exception: " + ex);
    }
  }

  @Test
  void testGetNonExistingServiceToken() throws Exception {
    final var nonExistingServiceRole = "non-existing-role-" + System.currentTimeMillis();

    final var serviceTokenSupplier =
        new VaultServiceTokenSupplier.Builder()
            .vaultAddress(vaultEnvironment.vaultAddr())
            .vaultTokenSupplier(() -> completedFuture(vaultEnvironment.login()))
            .serviceRole(nonExistingServiceRole)
            .serviceTokenNameBuilder((role, attributes) -> role)
            .build();

    try {
      serviceTokenSupplier.getToken(Collections.emptyMap()).get(3, TimeUnit.SECONDS);
      fail("Exception expected");
    } catch (ExecutionException e) {
      final var ex = e.getCause();
      assertNotNull(ex);
      assertNotNull(ex.getMessage());
      assertTrue(
          ex.getMessage().contains("Failed to get service token, status=400"), "Exception: " + ex);
    }
  }

  @Test
  void testGetServiceTokenByWrongServiceRole() throws Exception {
    final var now = System.currentTimeMillis();
    final var serviceRole1 = "role1-" + now;
    final var serviceRole2 = "role2-" + now;
    final var serviceRole3 = "role3-" + now;

    new VaultServiceRolesInstaller.Builder()
        .vaultAddress(vaultEnvironment.vaultAddr())
        .vaultTokenSupplier(() -> completedFuture(vaultEnvironment.login()))
        .keyNameSupplier(() -> "key-" + now)
        .roleNameBuilder(roleName -> roleName + "-" + now)
        .serviceRolesSources(
            List.of(
                () ->
                    new ServiceRoles()
                        .roles(
                            List.of(
                                newServiceRole(serviceRole1),
                                newServiceRole(serviceRole2),
                                newServiceRole(serviceRole3)))))
        .build()
        .install();

    final var serviceTokenSupplier =
        new VaultServiceTokenSupplier.Builder()
            .vaultAddress(vaultEnvironment.vaultAddr())
            .vaultTokenSupplier(() -> completedFuture(vaultEnvironment.login()))
            .serviceRole(serviceRole1)
            .serviceTokenNameBuilder((role, attributes) -> role)
            .build();

    try {
      serviceTokenSupplier.getToken(Collections.emptyMap()).get(3, TimeUnit.SECONDS);
      fail("Exception expected");
    } catch (ExecutionException e) {
      final var ex = e.getCause();
      assertNotNull(ex);
      assertNotNull(ex.getMessage());
      assertTrue(
          ex.getMessage().contains("Failed to get service token, status=400"), "Exception: " + ex);
    }
  }

  @Test
  void testGetServiceTokenSuccessfully() throws Exception {
    final var now = System.currentTimeMillis();
    final var serviceRole = "role-" + now;
    final var tags = Map.of("type", "ops", "ns", "develop");

    new VaultServiceRolesInstaller.Builder()
        .vaultAddress(vaultEnvironment.vaultAddr())
        .vaultTokenSupplier(() -> completedFuture(vaultEnvironment.login()))
        .keyNameSupplier(() -> "key-" + now)
        .roleNameBuilder(role -> toQualifiedName(role, tags))
        .serviceRolesSources(
            List.of(() -> new ServiceRoles().roles(List.of(newServiceRole(serviceRole)))))
        .build()
        .install();

    final var serviceTokenSupplier =
        new VaultServiceTokenSupplier.Builder()
            .vaultAddress(vaultEnvironment.vaultAddr())
            .vaultTokenSupplier(() -> completedFuture(vaultEnvironment.login()))
            .serviceRole(serviceRole)
            .serviceTokenNameBuilder(VaultServiceTokenTests::toQualifiedName)
            .build();

    final var serviceToken = serviceTokenSupplier.getToken(tags).get(3, TimeUnit.SECONDS);
    assertNotNull(serviceToken, "serviceToken");

    // Verify serviceToken

    final var jwtToken =
        new JsonwebtokenResolver(
                new JwksKeyLocator.Builder().jwksUri(vaultEnvironment.jwksUri()).build())
            .resolve(serviceToken)
            .get(3, TimeUnit.SECONDS);

    assertNotNull(jwtToken, "jwtToken");
    Assertions.assertTrue(jwtToken.header().size() > 0, "jwtToken.header: " + jwtToken.header());
    Assertions.assertTrue(jwtToken.payload().size() > 0, "jwtToken.payload: " + jwtToken.payload());
  }

  private static String toQualifiedName(String role, Map<String, String> tags) {
    return role + "-" + tags.get("type") + "-" + tags.get("ns");
  }

  private static Role newServiceRole(String name) {
    final var role = new ServiceRoles.Role();
    role.role(name);
    role.permissions(List.of("read", "write"));
    return role;
  }
}
