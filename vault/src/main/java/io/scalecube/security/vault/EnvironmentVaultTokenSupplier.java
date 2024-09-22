package io.scalecube.security.vault;

import com.bettercloud.vault.VaultConfig;
import java.util.Objects;

public class EnvironmentVaultTokenSupplier implements VaultTokenSupplier {

  public EnvironmentVaultTokenSupplier() {}

  public String getToken(VaultConfig config) {
    return Objects.requireNonNull(config.getToken(), "vault token");
  }
}
