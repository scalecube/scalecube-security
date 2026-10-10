package io.scalecube.security.vault;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultServiceTokenSupplier {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceTokenSupplier.class);

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private final String vaultAddress;
  private final String serviceRole;
  private final Supplier<CompletableFuture<String>> vaultTokenSupplier;
  private final BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder;
  private final int connectTimeoutSeconds;
  private final int readTimeoutSeconds;

  private VaultServiceTokenSupplier(Builder builder) {
    this.vaultAddress = Objects.requireNonNull(builder.vaultAddress, "vaultAddress");
    this.serviceRole = Objects.requireNonNull(builder.serviceRole, "serviceRole");
    this.vaultTokenSupplier =
        Objects.requireNonNull(builder.vaultTokenSupplier, "vaultTokenSupplier");
    this.serviceTokenNameBuilder =
        Objects.requireNonNull(builder.serviceTokenNameBuilder, "serviceTokenNameBuilder");
    this.connectTimeoutSeconds = builder.connectTimeoutSeconds;
    this.readTimeoutSeconds = builder.readTimeoutSeconds;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Obtains vault service token (aka identity token or oidc token).
   *
   * @param tags tags attributes, along with {@code serviceRole} will be applied on {@code
   *     serviceTokenNameBuilder}
   * @return vault service token
   */
  public CompletableFuture<String> getToken(Map<String, String> tags) {
    return vaultTokenSupplier
        .get()
        .thenApplyAsync(
            vaultToken -> {
              final var role = serviceTokenNameBuilder.apply(serviceRole, tags);
              final var uri = serviceTokenUri(vaultAddress, role);
              try {
                final var token = rpcGetToken(uri, vaultToken);
                if (LOGGER.isDebugEnabled()) {
                  LOGGER.debug("Got service token: {}, role: {}", mask(token), role);
                }
                return token;
              } catch (Exception ex) {
                throw new RuntimeException("Failed to get service token, role: " + role, ex);
              }
            });
  }

  private String rpcGetToken(String uri, String vaultToken) {
    try {
      final RestResponse response =
          new Rest()
              .header(VAULT_TOKEN_HEADER, vaultToken)
              .connectTimeoutSeconds(connectTimeoutSeconds)
              .readTimeoutSeconds(readTimeoutSeconds)
              .url(uri)
              .get();

      final var status = response.getStatus();
      final var body = new String(response.getBody(), StandardCharsets.UTF_8);
      if (status != 200) {
        throw new IllegalStateException(
            "Failed to get service token, status=" + status + ", body=" + body);
      }

      return Json.parse(body).asObject().get("data").asObject().get("token").asString();
    } catch (RestException e) {
      throw new RuntimeException(e);
    }
  }

  private static String serviceTokenUri(final String address, final String role) {
    return new StringJoiner("/", address, "").add("/v1/identity/oidc/token").add(role).toString();
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
    private Supplier<CompletableFuture<String>> vaultTokenSupplier;
    private BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder;
    private int connectTimeoutSeconds = 10;
    private int readTimeoutSeconds = 10;

    private Builder() {}

    /**
     * Setter for {@code vaultAddress}.
     *
     * @param vaultAddress vaultAddress
     * @return this
     */
    public Builder vaultAddress(String vaultAddress) {
      this.vaultAddress = vaultAddress;
      return this;
    }

    /**
     * Setter for {@code serviceRole}.
     *
     * @param serviceRole serviceRole
     * @return this
     */
    public Builder serviceRole(String serviceRole) {
      this.serviceRole = serviceRole;
      return this;
    }

    /**
     * Setter for {@code vaultTokenSupplier}.
     *
     * @param vaultTokenSupplier vaultTokenSupplier
     * @return this
     */
    public Builder vaultTokenSupplier(Supplier<CompletableFuture<String>> vaultTokenSupplier) {
      this.vaultTokenSupplier = vaultTokenSupplier;
      return this;
    }

    /**
     * Setter for {@code serviceTokenNameBuilder}.
     *
     * @param serviceTokenNameBuilder {@link BiFunction} where first parameter is service-role, and
     *     second parameter is map of attributes, and result will be fully qualified service-token
     *     name - a combination of service-role and attributes.
     * @return this
     */
    public Builder serviceTokenNameBuilder(
        BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder) {
      this.serviceTokenNameBuilder = serviceTokenNameBuilder;
      return this;
    }

    /**
     * Setter for {@code connectTimeoutSeconds} of vault http calls.
     *
     * @param connectTimeoutSeconds connectTimeoutSeconds (optional)
     * @return this
     */
    public Builder connectTimeoutSeconds(int connectTimeoutSeconds) {
      this.connectTimeoutSeconds = connectTimeoutSeconds;
      return this;
    }

    /**
     * Setter for {@code readTimeoutSeconds} of vault http calls.
     *
     * @param readTimeoutSeconds readTimeoutSeconds (optional)
     * @return this
     */
    public Builder readTimeoutSeconds(int readTimeoutSeconds) {
      this.readTimeoutSeconds = readTimeoutSeconds;
      return this;
    }

    public VaultServiceTokenSupplier build() {
      return new VaultServiceTokenSupplier(this);
    }
  }
}
