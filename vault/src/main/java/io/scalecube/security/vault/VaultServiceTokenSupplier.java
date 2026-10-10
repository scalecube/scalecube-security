package io.scalecube.security.vault;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultServiceTokenSupplier {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceTokenSupplier.class);

  private final String serviceRole;
  private final Supplier<CompletableFuture<String>> vaultTokenSupplier;
  private final BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder;
  private final VaultClient vaultClient;

  private VaultServiceTokenSupplier(Builder builder) {
    this.serviceRole = Objects.requireNonNull(builder.serviceRole, "serviceRole");
    this.vaultTokenSupplier =
        Objects.requireNonNull(builder.vaultTokenSupplier, "vaultTokenSupplier");
    this.serviceTokenNameBuilder =
        Objects.requireNonNull(builder.serviceTokenNameBuilder, "serviceTokenNameBuilder");
    this.vaultClient =
        new VaultClient(
            builder.vaultAddress,
            builder.httpClient != null
                ? builder.httpClient
                : VaultClient.newHttpClient(builder.connectTimeout),
            builder.requestTimeout);
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Obtains vault service token (aka identity token or oidc token).
   *
   * @param tags tags attributes, along with {@code serviceRole} will be applied on {@code
   *     serviceTokenNameBuilder}
   * @return vault service token, or failed future (with {@link VaultRequestException} if vault
   *     responded with error)
   */
  public CompletableFuture<String> getToken(Map<String, String> tags) {
    return vaultTokenSupplier
        .get()
        .thenCompose(
            vaultToken -> {
              final var role = serviceTokenNameBuilder.apply(serviceRole, tags);
              return vaultClient
                  .get(vaultToken, "identity", "oidc", "token", role)
                  .thenApply(
                      response -> {
                        final var token = response.path("data").path("token").textValue();
                        if (token == null) {
                          throw new IllegalStateException(
                              "Vault response has no data.token, role: " + role);
                        }
                        if (LOGGER.isDebugEnabled()) {
                          LOGGER.debug("Got service token: {}, role: {}", mask(token), role);
                        }
                        return token;
                      });
            });
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
    private Duration connectTimeout = Duration.ofSeconds(10);
    private Duration requestTimeout = Duration.ofSeconds(10);
    private HttpClient httpClient;

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
     * Setter for {@code connectTimeout} of vault http calls. Ignored if {@code httpClient} is set.
     *
     * @param connectTimeout connectTimeout (optional)
     * @return this
     */
    public Builder connectTimeout(Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
      return this;
    }

    /**
     * Setter for {@code requestTimeout} of vault http calls.
     *
     * @param requestTimeout requestTimeout (optional)
     * @return this
     */
    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    /**
     * Setter for optional {@link HttpClient}. It should follow redirects ({@link
     * HttpClient.Redirect#NORMAL}), as vault standby nodes may redirect to the active node.
     *
     * @param httpClient httpClient
     * @return this
     */
    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = httpClient;
      return this;
    }

    public VaultServiceTokenSupplier build() {
      return new VaultServiceTokenSupplier(this);
    }
  }
}
