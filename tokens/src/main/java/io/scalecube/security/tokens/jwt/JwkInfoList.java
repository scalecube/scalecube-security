package io.scalecube.security.tokens.jwt;

import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

public class JwkInfoList {

  private final List<JwkInfo> keys;

  public JwkInfoList() {
    this(null);
  }

  public JwkInfoList(List<JwkInfo> keys) {
    this.keys = keys != null ? new ArrayList<>(keys) : null;
  }

  public List<JwkInfo> keys() {
    return keys;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", JwkInfoList.class.getSimpleName() + "[", "]")
        .add("keys=" + (keys != null ? "[" + keys.size() + "]" : null))
        .toString();
  }
}
