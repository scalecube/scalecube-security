package io.scalecube.security;

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

  /**
   * Profile constructor.
   *
   * @param userId of the user.
   * @param tenant of the user.
   * @param email of the user.
   * @param isEmailVerified of the user.
   * @param name of the user.
   * @param familyName of the user.
   * @param givenName of the user.
   * @param claims claims as key values.
   */
  private Profile(String userId, String tenant, String email, Boolean isEmailVerified, String name,
      String familyName, String givenName, Map<String, Object> claims) {
    this.userId = userId;
    this.tenant = tenant;
    this.email = email;
    this.isEmailVerified = isEmailVerified;
    this.name = name;
    this.familyName = familyName;
    this.givenName = givenName;
    this.claims = claims;
  }

  public String getUserId() {
    return userId;
  }

  public String getTenant() {
    return tenant;
  }

  public String getEmail() {
    return email;
  }

  public boolean isEmailVerified() {
    return isEmailVerified;
  }

  public String getName() {
    return name;
  }

  public String getFamilyName() {
    return familyName;
  }

  public String getGivenName() {
    return givenName;
  }

  public Map<String, Object> getClaims() {
    return claims;
  }

  @Override
  public String toString() {
    return super.toString()
            + String.format(" ["
            + "tenant=%s, "
            + "email=%s, "
            + "isEmailVerified=%s, "
            + "name=%s, "
            + "familyName=%s, "
            + "givenName=%s, "
            + "claims=%s]",
            userId,
            tenant,
            email,
            isEmailVerified,
            name,
            familyName,
            givenName,
            claims);
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
      return new Profile(userId, tenant,email, isEmailVerified, name, familyName, givenName,
          claims);
    }
  }
}

