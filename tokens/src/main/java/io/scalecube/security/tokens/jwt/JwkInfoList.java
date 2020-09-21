package io.scalecube.security.tokens.jwt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringJoiner;

public class JwkInfoList {

  private List<JwkInfo> keys = Collections.emptyList();

  public JwkInfoList() {}

  public JwkInfoList(List<JwkInfo> keys) {
    this.keys = new ArrayList<>(keys);
  }

  public List<JwkInfo> keys() {
    return keys;
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", JwkInfoList.class.getSimpleName() + "[", "]")
        .add("keys=" + keys)
        .toString();
  }
}
