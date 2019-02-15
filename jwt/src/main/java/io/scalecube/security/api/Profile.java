package io.scalecube.security.api;

import java.util.Map;

public class Profile {

  private final String userId;
  private final String tenant;
  private final String email;
  private final boolean isEmailVerified;
  private final String name;
  private final String familyName;
  private final String givenName;
  private final Map<String, Object> claims;

  private Profile(Builder builder) {
    this.userId = builder.userId;
    this.tenant = builder.tenant;
    this.email = builder.email;
    this.isEmailVerified = builder.isEmailVerified;
    this.name = builder.name;
    this.familyName = builder.familyName;
    this.givenName = builder.givenName;
    this.claims = builder.claims;
  }

  public String userId() {
    return userId;
  }

  public String tenant() {
    return tenant;
  }

  public String email() {
    return email;
  }

  public boolean isEmailVerified() {
    return isEmailVerified;
  }

  public String name() {
    return name;
  }

  public String familyName() {
    return familyName;
  }

  public String givenName() {
    return givenName;
  }

  public Object claim(String name) {
    return this.claims.get(name);
  }
  
  public Map<String, Object> claims() {
    return claims;
  }

  @Override
  public String toString() {
    return super.toString()
        + String.format(
            " ["
                + "userId=%s, "
                + "tenant=%s, "
                + "email=%s, "
                + "isEmailVerified=%s, "
                + "name=%s, "
                + "familyName=%s, "
                + "givenName=%s, "
                + "claims=%s]",
            userId, tenant, email, isEmailVerified, name, familyName, givenName, claims);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String userId;
    private String tenant;
    private String email;
    private boolean isEmailVerified;
    private String name;
    private String familyName;
    private String givenName;
    private Map<String, Object> claims;

    private Builder() {}

    public Builder userId(String userId) {
      this.userId = userId;
      return this;
    }

    public Builder tenant(String tenant) {
      this.tenant = tenant;
      return this;
    }

    public Builder email(String email) {
      this.email = email;
      return this;
    }

    public Builder emailVerified(Boolean emailVerified) {
      isEmailVerified = emailVerified != null ? emailVerified.booleanValue() : Boolean.FALSE;
      return this;
    }

    public Builder name(String name) {
      this.name = name;
      return this;
    }

    public Builder familyName(String familyName) {
      this.familyName = familyName;
      return this;
    }

    public Builder givenName(String givenName) {
      this.givenName = givenName;
      return this;
    }

    public Builder claims(Map<String, Object> claims) {
      this.claims = claims;
      return this;
    }

    public Profile build() {
      return new Profile(this);
    }
  }
}
