package io.scalecube.security.tokens.jwt;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import java.io.IOException;
import java.util.UUID;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.vault.VaultContainer;

public class VaultEnvironment {

  private static final String VAULT_TOKEN = "test";
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private static final GenericContainer VAULT_CONTAINER =
      new VaultContainer("vault:1.4.0")
          .withVaultToken(VAULT_TOKEN)
          .waitingFor(new LogMessageWaitStrategy().withRegEx("^.*Vault server started!.*$"));

  private static String vaultAddr;

  public static void start() {
    VAULT_CONTAINER.start();
    vaultAddr = "http://localhost:" + VAULT_CONTAINER.getMappedPort(8200);
  }

  public static void stop() {
    VAULT_CONTAINER.stop();
  }

  public static String generateIdentityToken(String clientToken, String roleName)
      throws RestException {
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

  public static void createIdentityTokenPolicy(String roleName) throws RestException {
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

  public static String createEntity(final String roleName)
      throws IOException, InterruptedException {

    checkSuccess(
        VAULT_CONTAINER.execInContainer("vault auth enable userpass".split("\\s")).getExitCode());
    checkSuccess(
        VAULT_CONTAINER
            .execInContainer(
                ("vault write auth/userpass/users/abc password=abc policies=" + roleName)
                    .split("\\s"))
            .getExitCode());

    ExecResult loginExecResult =
        VAULT_CONTAINER.execInContainer(
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

  public static String createIdentityKey() throws RestException {
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

  public static String createIdentityRole(String keyName) throws RestException {
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

  public static String oidcKeyUrl(String keyName) {
    return vaultAddr + "/v1/identity/oidc/key/" + keyName;
  }

  public static String oidcRoleUrl(String roleName) {
    return vaultAddr + "/v1/identity/oidc/role/" + roleName;
  }

  public static String oidcToken(String roleName) {
    return vaultAddr + "/v1/identity/oidc/token/" + roleName;
  }

  public static String jwksUri() {
    return vaultAddr + "/v1/identity/oidc/.well-known/keys";
  }

  public static String policiesAclUri(String roleName) {
    return vaultAddr + "/v1/sys/policies/acl/" + roleName;
  }
}
