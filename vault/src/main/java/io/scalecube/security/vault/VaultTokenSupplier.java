package io.scalecube.security.vault;

import com.bettercloud.vault.VaultConfig;

@FunctionalInterface
public interface VaultTokenSupplier {

  String getToken(VaultConfig config);
}
