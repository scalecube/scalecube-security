package io.scalecube.security.vault;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public class VaultClientTokenSupplier {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultClientTokenSupplier.class);

  private final String vaultAddress;
  private final String vaultToken;
  private final String vaultRole;

  /**
   * Constructor.
   *
   * @param vaultAddress vaultAddress
   * @param vaultToken vaultToken (must not set be together with vaultRole)
   * @param vaultRole vaultRole (must not set be together with vaultToken)
   */
  public VaultClientTokenSupplier(String vaultAddress, String vaultToken, String vaultRole) {
    this.vaultAddress = vaultAddress;
    this.vaultToken = vaultToken;
    this.vaultRole = vaultRole;
    if (isNullOrNoneOrEmpty(vaultAddress)) {
      throw new IllegalArgumentException("Vault address is required");
    }
    if (isNullOrNoneOrEmpty(vaultToken) && isNullOrNoneOrEmpty(vaultRole)) {
      throw new IllegalArgumentException(
          "Vault auth scheme is required (specify either vaultToken or vaultRole)");
    }
  }

  /**
   * Returns new instance of {@link VaultClientTokenSupplier}.
   *
   * @param vaultAddress vaultAddress
   * @param vaultToken vaultToken
   * @return new instance of {@link VaultClientTokenSupplier}
   */
  public static VaultClientTokenSupplier supplierByToken(String vaultAddress, String vaultToken) {
    return new VaultClientTokenSupplier(vaultAddress, vaultToken, null);
  }

  /**
   * Returns new instance of {@link VaultClientTokenSupplier}.
   *
   * @param vaultAddress vaultAddress
   * @param vaultRole vaultRole
   * @return new instance of {@link VaultClientTokenSupplier}
   */
  public static VaultClientTokenSupplier supplierByRole(String vaultAddress, String vaultRole) {
    return new VaultClientTokenSupplier(vaultAddress, null, vaultRole);
  }

  /**
   * Obtains vault client token.
   *
   * @return vault client token
   */
  public Mono<String> getToken() {
    return Mono.fromCallable(this::getToken0)
        .subscribeOn(Schedulers.boundedElastic())
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
                  + "(specify either vaultToken or vaultRole, not both)");
        }
        vaultTokenSupplier = new KubernetesVaultTokenSupplier().vaultRole(vaultRole);
        vaultConfig = new VaultConfig().address(vaultAddress).build();
      } else {
        vaultTokenSupplier = new EnvironmentVaultTokenSupplier();
        vaultConfig = new VaultConfig().address(vaultAddress).token(vaultToken).build();
      }

      return vaultTokenSupplier.getToken(vaultConfig);
    } catch (VaultException e) {
      throw Exceptions.propagate(e);
    }
  }

  private static boolean isNullOrNoneOrEmpty(String value) {
    return Objects.isNull(value)
        || "none".equalsIgnoreCase(value)
        || "null".equals(value)
        || value.isEmpty();
  }

  private static String mask(String data) {
    if (data == null || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }
}
