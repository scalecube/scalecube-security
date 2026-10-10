package io.scalecube.security.vault;

import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import io.scalecube.security.vault.VaultServiceRolesInstaller.ServiceRoles;
import io.scalecube.security.vault.VaultServiceRolesInstaller.ServiceRoles.Role;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class VaultServiceRolesInstallerTests {

  private final AtomicInteger roleRequests = new AtomicInteger();
  private HttpServer server;

  @BeforeEach
  void beforeEach() throws IOException {
    server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    server.createContext(
        "/v1/identity/oidc/key/",
        httpCall -> {
          try {
            Thread.sleep(500);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          httpCall.sendResponseHeaders(204, -1);
          httpCall.close();
        });
    server.createContext(
        "/v1/identity/oidc/role/",
        httpCall -> {
          roleRequests.incrementAndGet();
          httpCall.sendResponseHeaders(204, -1);
          httpCall.close();
        });
    server.start();
  }

  @AfterEach
  void afterEach() {
    server.stop(0);
  }

  @Test
  void testTimeoutStopsRemainingRequests() throws Exception {
    final var installer =
        VaultServiceRolesInstaller.builder()
            .vaultAddress("http://localhost:" + server.getAddress().getPort())
            .vaultTokenSupplier(() -> completedFuture("token"))
            .keyNameSupplier(() -> "key")
            .roleNameBuilder(role -> role)
            .serviceRolesSources(
                List.of(
                    () ->
                        new ServiceRoles()
                            .roles(
                                List.of(
                                    new Role().role("role1").permissions(List.of("read")),
                                    new Role().role("role2").permissions(List.of("read"))))))
            .requestTimeout(Duration.ofSeconds(2))
            .timeout(100, TimeUnit.MILLISECONDS)
            .build();

    final var ex = assertThrows(RuntimeException.class, installer::install);
    assertInstanceOf(TimeoutException.class, ex.getCause());

    // key request completes after the timeout; role requests must not be sent
    Thread.sleep(1000);
    assertEquals(0, roleRequests.get());
  }
}
