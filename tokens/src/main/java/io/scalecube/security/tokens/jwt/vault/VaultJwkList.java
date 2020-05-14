package io.scalecube.security.tokens.jwt.vault;

import java.util.List;
import java.util.StringJoiner;

public class VaultJwkList {

  private List<VaultJwk> keys;

  /**
   * Serialization only constructor.
   *
   * @deprecated not to be used
   */
  public VaultJwkList() {}

  public List<VaultJwk> keys() {
    return keys;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", VaultJwkList.class.getSimpleName() + "[", "]")
        .add("keys=" + keys)
        .toString();
  }
}
