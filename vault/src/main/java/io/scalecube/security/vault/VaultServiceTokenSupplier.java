package io.scalecube.security.vault;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultServiceTokenSupplier {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceTokenSupplier.class);

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private final String vaultAddress;
  private final String serviceRole;
  private final Supplier<String> vaultTokenSupplier;
  private final BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder;

  private VaultServiceTokenSupplier(Builder builder) {
    this.vaultAddress = Objects.requireNonNull(builder.vaultAddress, "vaultAddress");
    this.serviceRole = Objects.requireNonNull(builder.serviceRole, "serviceRole");
    this.vaultTokenSupplier =
        Objects.requireNonNull(builder.vaultTokenSupplier, "vaultTokenSupplier");
    this.serviceTokenNameBuilder =
        Objects.requireNonNull(builder.serviceTokenNameBuilder, "serviceTokenNameBuilder");
  }

  /**
   * Obtains vault service token (aka identity token or oidc token).
   *
   * @param tags tags attributes, along with {@code serviceRole} will be applied on {@code
   *     serviceTokenNameBuilder}
   * @return vault service token
   */
  public String getToken(Map<String, String> tags) {
    try {
      final String vaultToken = vaultTokenSupplier.get();
      final String uri = toServiceTokenUri(tags);
      final String token = rpcGetToken(uri, vaultToken);
      LOGGER.debug("[getToken][success] uri={}, tags={}, result={}", uri, tags, mask(token));
      return token;
    } catch (Exception ex) {
      LOGGER.error("[getToken][error] tags={}, cause: {}", tags, ex.toString());
      throw new RuntimeException(ex);
    }
  }

  private static String rpcGetToken(String uri, String vaultToken) {
    try {
      final RestResponse response =
          new Rest().header(VAULT_TOKEN_HEADER, vaultToken).url(uri).get();

      verifyOk(response.getStatus());

      return Json.parse(new String(response.getBody()))
          .asObject()
          .get("data")
          .asObject()
          .get("token")
          .asString();
    } catch (RestException e) {
      throw new RuntimeException(e);
    }
  }

  private static void verifyOk(int status) {
    if (status != 200) {
      LOGGER.error("[rpcGetToken] Not expected status ({}) returned", status);
      throw new IllegalStateException("Not expected status returned, status=" + status);
    }
  }

  private String toServiceTokenUri(Map<String, String> tags) {
    return new StringJoiner("/", vaultAddress, "")
        .add("/v1/identity/oidc/token")
        .add(serviceTokenNameBuilder.apply(serviceRole, tags))
        .toString();
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }

  public static class Builder {

    private String vaultAddress;
    private String serviceRole;
    private Supplier<String> vaultTokenSupplier;
    private BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder;

    private Builder() {}

    public Builder vaultAddress(String vaultAddress) {
      this.vaultAddress = vaultAddress;
      return this;
    }

    public Builder serviceRole(String serviceRole) {
      this.serviceRole = serviceRole;
      return this;
    }

    public Builder vaultTokenSupplier(Supplier<String> vaultTokenSupplier) {
      this.vaultTokenSupplier = vaultTokenSupplier;
      return this;
    }

    public Builder serviceTokenNameBuilder(
        BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder) {
      this.serviceTokenNameBuilder = serviceTokenNameBuilder;
      return this;
    }

    public VaultServiceTokenSupplier builder() {
      return new VaultServiceTokenSupplier(this);
    }
  }
}
