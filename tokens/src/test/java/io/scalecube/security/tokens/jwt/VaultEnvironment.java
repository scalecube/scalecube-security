package io.scalecube.security.tokens.jwt;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import java.util.UUID;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.vault.VaultContainer;

public class VaultEnvironment implements AutoCloseable {

  private static final String VAULT_TOKEN = "test";
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  private static final int PORT = 8200;

  private final GenericContainer vault =
      new VaultContainer("vault:1.4.0")
          .withVaultToken(VAULT_TOKEN)
          .waitingFor(new LogMessageWaitStrategy().withRegEx("^.*Vault server started!.*$"));

  private String vaultAddr;

  public static VaultEnvironment start() {
    final var environment = new VaultEnvironment();
    try {
      final var vault = environment.vault;
      vault.start();
      environment.vaultAddr = "http://localhost:" + vault.getMappedPort(PORT);
      checkSuccess(vault.execInContainer("vault auth enable userpass".split("\\s")).getExitCode());
    } catch (Exception ex) {
      environment.close();
      throw new RuntimeException(ex);
    }
    return environment;
  }

  public String generateIdentityToken(String clientToken, String roleName) throws RestException {
    RestResponse restResponse =
        new Rest().header(VAULT_TOKEN_HEADER, clientToken).url(oidcToken(roleName)).get();
    int status = restResponse.getStatus();

    if (status != 200 && status != 204) {
      throw new IllegalStateException(
          "Unexpected status code on identity token creation: " + status);
    }

    return Json.parse(new String(restResponse.getBody()))
        .asObject()
        .get("data")
        .asObject()
        .get("token")
        .asString();
  }

  public void createIdentityTokenPolicy(String roleName) throws RestException {
    int status =
        new Rest()
            .header(VAULT_TOKEN_HEADER, VAULT_TOKEN)
            .url(policiesAclUri(roleName))
            .body(
                ("{\"policy\":\"path \\\"identity/oidc/token/"
                        + roleName
                        + "\\\" {capabilities=[\\\"create\\\", \\\"read\\\"]}\"}")
                    .getBytes())
            .post()
            .getStatus();

    if (status != 200 && status != 204) {
      throw new IllegalStateException(
          "Unexpected status code on identity token policy creation: " + status);
    }
  }

  public String createEntity(final String roleName) throws Exception {
    checkSuccess(
        vault
            .execInContainer(
                ("vault write auth/userpass/users/abc password=abc policies=" + roleName)
                    .split("\\s"))
            .getExitCode());
    ExecResult loginExecResult =
        vault.execInContainer(
            "vault login -format json -method=userpass username=abc password=abc".split("\\s"));
    checkSuccess(loginExecResult.getExitCode());
    return Json.parse(loginExecResult.getStdout().replaceAll("\\r?\\n", ""))
        .asObject()
        .get("auth")
        .asObject()
        .get("client_token")
        .asString();
  }

  public static void checkSuccess(int exitCode) {
    if (exitCode != 0) {
      throw new IllegalStateException("Exited with error: " + exitCode);
    }
  }

  public String createIdentityKey() throws RestException {
    String keyName = UUID.randomUUID().toString();
    int status =
        new Rest()
            .header(VAULT_TOKEN_HEADER, VAULT_TOKEN)
            .url(oidcKeyUrl(keyName))
            .body(
                ("{\"rotation_period\":\""
                        + "1m"
                        + "\", "
                        + "\"verification_ttl\": \""
                        + "1m"
                        + "\", "
                        + "\"allowed_client_ids\": \"*\", "
                        + "\"algorithm\": \"RS256\"}")
                    .getBytes())
            .post()
            .getStatus();

    if (status != 200 && status != 204) {
      throw new IllegalStateException("Unexpected status code on oidc/key creation: " + status);
    }
    return keyName;
  }

  public String createIdentityRole(String keyName) throws RestException {
    String roleName = UUID.randomUUID().toString();
    int status =
        new Rest()
            .header(VAULT_TOKEN_HEADER, VAULT_TOKEN)
            .url(oidcRoleUrl(roleName))
            .body(("{\"key\":\"" + keyName + "\",\"ttl\": \"" + "1h" + "\"}").getBytes())
            .post()
            .getStatus();

    if (status != 200 && status != 204) {
      throw new IllegalStateException("Unexpected status code on oidc/role creation: " + status);
    }
    return roleName;
  }

  public String oidcKeyUrl(String keyName) {
    return vaultAddr + "/v1/identity/oidc/key/" + keyName;
  }

  public String oidcRoleUrl(String roleName) {
    return vaultAddr + "/v1/identity/oidc/role/" + roleName;
  }

  public String oidcToken(String roleName) {
    return vaultAddr + "/v1/identity/oidc/token/" + roleName;
  }

  public String jwksUri() {
    return vaultAddr + "/v1/identity/oidc/.well-known/keys";
  }

  public String policiesAclUri(String roleName) {
    return vaultAddr + "/v1/sys/policies/acl/" + roleName;
  }

  @Override
  public void close() {
    vault.stop();
  }
}
