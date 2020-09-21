package io.scalecube.security.tokens.jwt;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.vault.VaultContainer;
import reactor.test.StepVerifier;

class JwksKeyProviderTests extends BaseTest {

  private static final String VAULT_TOKEN = "test";
  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private static final GenericContainer VAULT_CONTAINER =
      new VaultContainer("vault:1.4.0")
          .withVaultToken(VAULT_TOKEN)
          .waitingFor(new LogMessageWaitStrategy().withRegEx("^.*Vault server started!.*$"));

  private static String vaultAddr;

  @BeforeAll
  static void beforeAll() {
    VAULT_CONTAINER.start();
    vaultAddr = "http://localhost:" + VAULT_CONTAINER.getMappedPort(8200);
  }

  @AfterAll
  static void afterAll() {
    VAULT_CONTAINER.stop();
  }

  @Test
  void testJwksKeysRetrieval() throws RestException, IOException, InterruptedException {
    String keyName = createIdentityKey(vaultAddr); // oidc/key
    String roleName = createIdentityRole(vaultAddr, keyName); // oidc/role
    createIdentityTokenPolicy(roleName); // write policy policyfile.hcl
    String clientToken = createEntity(roleName); // onboard some entity with policy line above
    String token = generateIdentityToken(clientToken, roleName); // oidc/token
    String kid = getKid(token);

    JwksKeyProvider keyProvider = new JwksKeyProvider(jwksUri(vaultAddr));

    StepVerifier.create(keyProvider.findKey(kid)).expectNextCount(1).expectComplete().verify();
  }

  @Test
  void testJwksKeysRetrievalKeyNotFound() {
    JwksKeyProvider keyProvider = new JwksKeyProvider(jwksUri(vaultAddr));

    StepVerifier.create(keyProvider.findKey(UUID.randomUUID().toString()))
        .expectErrorMatches(
            th -> th.getMessage() != null && th.getMessage().contains("Key was not found"))
        .verify();
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

  private static String generateIdentityToken(String clientToken, String roleName)
      throws RestException {
    RestResponse restResponse =
        new Rest()
            .header(VAULT_TOKEN_HEADER, clientToken)
            .url(oidcToken(vaultAddr, roleName))
            .get();
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

  private static void createIdentityTokenPolicy(String roleName) throws RestException {
    int status =
        new Rest()
            .header(VAULT_TOKEN_HEADER, VAULT_TOKEN)
            .url(policiesAclUri(vaultAddr, roleName))
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

  private static String createEntity(final String roleName)
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

  private static void checkSuccess(int exitCode) {
    if (exitCode != 0) {
      throw new IllegalStateException("Exited with error: " + exitCode);
    }
  }

  private static String createIdentityKey(String vaultAddr) throws RestException {
    return createIdentityKey(vaultAddr, "1m", "1m");
  }

  private static String createIdentityKey(
      String vaultAddr, String rotationPeriod, String verificationTtl) throws RestException {
    String keyName = UUID.randomUUID().toString();
    int status =
        new Rest()
            .header(VAULT_TOKEN_HEADER, VAULT_TOKEN)
            .url(oidcKeyUrl(vaultAddr, keyName))
            .body(
                ("{\"rotation_period\":\""
                        + rotationPeriod
                        + "\", "
                        + "\"verification_ttl\": \""
                        + verificationTtl
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

  private static String createIdentityRole(String vaultAddr, String keyName) throws RestException {
    return createIdentityRole(vaultAddr, keyName, "1h");
  }

  private static String createIdentityRole(String vaultAddr, String keyName, String ttl)
      throws RestException {
    String roleName = UUID.randomUUID().toString();
    int status =
        new Rest()
            .header(VAULT_TOKEN_HEADER, VAULT_TOKEN)
            .url(oidcRoleUrl(vaultAddr, roleName))
            .body(("{\"key\":\"" + keyName + "\",\"ttl\": \"" + ttl + "\"}").getBytes())
            .post()
            .getStatus();

    if (status != 200 && status != 204) {
      throw new IllegalStateException("Unexpected status code on oidc/role creation: " + status);
    }
    return roleName;
  }

  private static String oidcKeyUrl(String vaultAddr, String keyName) {
    return vaultAddr + "/v1/identity/oidc/key/" + keyName;
  }

  private static String oidcRoleUrl(String vaultAddr, String roleName) {
    return vaultAddr + "/v1/identity/oidc/role/" + roleName;
  }

  private static String oidcToken(String vaultAddr, String roleName) {
    return vaultAddr + "/v1/identity/oidc/token/" + roleName;
  }

  private static String jwksUri(String vaultAddr) {
    return vaultAddr + "/v1/identity/oidc/.well-known/keys";
  }

  private static String policiesAclUri(String vaultAddr, String roleName) {
    return vaultAddr + "/v1/sys/policies/acl/" + roleName;
  }
}
