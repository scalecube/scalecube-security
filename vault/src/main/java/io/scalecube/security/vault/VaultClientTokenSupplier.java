package io.scalecube.security.vault;

import static io.scalecube.utils.MaskUtil.mask;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import io.scalecube.config.utils.ThrowableUtil;
import io.scalecube.config.vault.EnvironmentVaultTokenSupplier;
import io.scalecube.config.vault.KubernetesVaultTokenSupplier;
import io.scalecube.config.vault.VaultTokenSupplier;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public final class VaultClientTokenSupplier {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultClientTokenSupplier.class);

  private String vaultAddress;
  private String vaultToken;
  private String vaultRole;

  public VaultClientTokenSupplier() {}

  private VaultClientTokenSupplier(VaultClientTokenSupplier other) {
    this.vaultAddress = other.vaultAddress;
    this.vaultToken = other.vaultToken;
    this.vaultRole = other.vaultRole;
  }

  private VaultClientTokenSupplier copy() {
    return new VaultClientTokenSupplier(this);
  }

  private void validate() {
    if (isNullOrNoneOrEmpty(vaultAddress)) {
      throw new IllegalArgumentException("Vault address is required");
    }
    if (isNullOrNoneOrEmpty(vaultToken) && isNullOrNoneOrEmpty(vaultRole)) {
      throw new IllegalArgumentException(
          "Vault auth scheme is required (specify either VAULT_ROLE or VAULT_TOKEN)");
    }
  }

  /**
   * Setter for vaultAddress.
   *
   * @param vaultAddress vaultAddress
   * @return new instance with applied setting
   */
  public VaultClientTokenSupplier vaultAddress(String vaultAddress) {
    final VaultClientTokenSupplier c = copy();
    c.vaultAddress = vaultAddress;
    return c;
  }

  /**
   * Setter for vaultToken.
   *
   * @param vaultToken vaultToken
   * @return new instance with applied setting
   */
  public VaultClientTokenSupplier vaultToken(String vaultToken) {
    final VaultClientTokenSupplier c = copy();
    c.vaultToken = vaultToken;
    return c;
  }

  /**
   * Setter for vaultRole.
   *
   * @param vaultRole vaultRole
   * @return new instance with applied setting
   */
  public VaultClientTokenSupplier vaultRole(String vaultRole) {
    final VaultClientTokenSupplier c = copy();
    c.vaultRole = vaultRole;
    return c;
  }

  /**
   * Obtains vault client token.
   *
   * @return vault client token
   */
  public Mono<String> getToken() {
    return Mono.fromRunnable(this::validate)
        .then(Mono.fromCallable(this::getToken0))
        .subscribeOn(Schedulers.boundedElastic())
        .doOnSubscribe(s -> LOGGER.debug("[getToken] Getting vault client token"))
        .doOnSuccess(s -> LOGGER.debug("[getToken][success] result: {}", mask(s)))
        .doOnError(th -> LOGGER.error("[getToken][error] cause: {}", th.toString()));
  }

  private String getToken0() {
    try {
      VaultTokenSupplier vaultTokenSupplier;
      VaultConfig vaultConfig;

      if (!isNullOrNoneOrEmpty(vaultRole)) {
        if (!isNullOrNoneOrEmpty(vaultToken)) {
          LOGGER.warn(
              "Taking KubernetesVaultTokenSupplier by precedence rule, "
                  + "ignoring EnvironmentVaultTokenSupplier "
                  + "(specify either VAULT_ROLE or VAULT_TOKEN, not both)");
        }
        vaultTokenSupplier = new KubernetesVaultTokenSupplier().vaultRole(vaultRole);
        vaultConfig = new VaultConfig().address(vaultAddress).build();
      } else {
        vaultTokenSupplier = new EnvironmentVaultTokenSupplier();
        vaultConfig = new VaultConfig().address(vaultAddress).token(vaultToken).build();
      }

      return vaultTokenSupplier.getToken(vaultConfig);
    } catch (VaultException e) {
      throw ThrowableUtil.propagate(e);
    }
  }

  private static boolean isNullOrNoneOrEmpty(String value) {
    return Objects.isNull(value)
        || "none".equalsIgnoreCase(value)
        || "null".equals(value)
        || value.isEmpty();
  }
}
