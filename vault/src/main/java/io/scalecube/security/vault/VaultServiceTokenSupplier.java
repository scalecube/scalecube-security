package io.scalecube.security.vault;

import static io.scalecube.utils.MaskUtil.mask;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.function.BiFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public final class VaultServiceTokenSupplier {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceTokenSupplier.class);

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private String serviceRole;
  private String vaultAddress;
  private Mono<String> vaultTokenSupplier;
  private BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder;

  public VaultServiceTokenSupplier() {}

  private VaultServiceTokenSupplier(VaultServiceTokenSupplier other) {
    this.serviceRole = other.serviceRole;
    this.vaultAddress = other.vaultAddress;
    this.vaultTokenSupplier = other.vaultTokenSupplier;
    this.serviceTokenNameBuilder = other.serviceTokenNameBuilder;
  }

  private VaultServiceTokenSupplier copy() {
    return new VaultServiceTokenSupplier(this);
  }

  private void validate() {
    Objects.requireNonNull(serviceRole, "VaultServiceTokenSupplier.serviceRole");
    Objects.requireNonNull(vaultAddress, "VaultServiceTokenSupplier.vaultAddress");
    Objects.requireNonNull(vaultTokenSupplier, "VaultServiceTokenSupplier.vaultTokenSupplier");
    Objects.requireNonNull(
        serviceTokenNameBuilder, "VaultServiceTokenSupplier.serviceTokenNameBuilder");
  }

  /**
   * Setter for serviceRole.
   *
   * @param serviceRole serviceRole
   * @return new instance with applied setting
   */
  public VaultServiceTokenSupplier serviceRole(String serviceRole) {
    final VaultServiceTokenSupplier c = copy();
    c.serviceRole = serviceRole;
    return c;
  }

  /**
   * Setter for vaultAddress.
   *
   * @param vaultAddress vaultAddress
   * @return new instance with applied setting
   */
  public VaultServiceTokenSupplier vaultAddress(String vaultAddress) {
    final VaultServiceTokenSupplier c = copy();
    c.vaultAddress = vaultAddress;
    return c;
  }

  /**
   * Setter for vaultTokenSupplier.
   *
   * @param vaultTokenSupplier vaultTokenSupplier
   * @return new instance with applied setting
   */
  public VaultServiceTokenSupplier vaultTokenSupplier(Mono<String> vaultTokenSupplier) {
    final VaultServiceTokenSupplier c = copy();
    c.vaultTokenSupplier = vaultTokenSupplier;
    return c;
  }

  /**
   * Setter for serviceTokenNameBuilder.
   *
   * @param serviceTokenNameBuilder serviceTokenNameBuilder; inputs for this function are {@code
   *     serviceRole} and {@code tags} attributes
   * @return new instance with applied setting
   */
  public VaultServiceTokenSupplier serviceTokenNameBuilder(
      BiFunction<String, Map<String, String>, String> serviceTokenNameBuilder) {
    final VaultServiceTokenSupplier c = copy();
    c.serviceTokenNameBuilder = serviceTokenNameBuilder;
    return c;
  }

  /**
   * Obtains vault service token (aka identity token or oidc token).
   *
   * @param tags tags attributes; along with {@code serviceRole} will be applied on {@code
   *     serviceTokenNameBuilder}
   * @return vault service token
   */
  public Mono<String> getToken(Map<String, String> tags) {
    return Mono.fromRunnable(this::validate)
        .then(Mono.defer(() -> vaultTokenSupplier))
        .subscribeOn(Schedulers.boundedElastic())
        .flatMap(
            vaultToken -> {
              final String uri = buildServiceTokenUri(tags);
              return Mono.fromCallable(() -> rpcGetToken(uri, vaultToken))
                  .doOnSuccess(
                      s ->
                          LOGGER.debug(
                              "[getToken][success] uri='{}', tags={}, result: {}",
                              uri,
                              tags,
                              mask(s)))
                  .doOnError(
                      th ->
                          LOGGER.error(
                              "[getToken][error] uri='{}', tags={}, cause: {}",
                              uri,
                              tags,
                              th.toString()));
            });
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
      throw Exceptions.propagate(e);
    }
  }

  private static void verifyOk(int status) {
    if (status != 200) {
      LOGGER.error("[rpcGetToken] Not expected status ({}) returned", status);
      throw new IllegalStateException("Not expected status returned, status=" + status);
    }
  }

  private String buildServiceTokenUri(Map<String, String> tags) {
    return new StringJoiner("/", vaultAddress, "")
        .add("/v1/identity/oidc/token")
        .add(serviceTokenNameBuilder.apply(serviceRole, tags))
        .toString();
  }
}
