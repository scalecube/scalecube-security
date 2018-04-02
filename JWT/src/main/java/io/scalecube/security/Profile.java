package io.scalecube.security;

import java.util.Map;

public class Profile {

    private final String userId;
    private final String tenant;
    private final String email;
    private final Boolean isEmaildVerified;
    private final String name;
    private final String familyName;
    private final String givenName;
    private final Map<String, Object> claims;

    public Profile(String userId, String tenant, String email, Boolean isEmaildVerified, String name, String familyName, String givenName, Map<String, Object> claims) {
        this.userId = userId;
        this.tenant = tenant;
        this.email = email;
        this.isEmaildVerified = isEmaildVerified;
        this.name = name;
        this.familyName = familyName;
        this.givenName = givenName;
        this.claims = claims;
    }

    public String getUserId() { return userId; }

    public String getTenant() { return tenant; }

    public String getEmail()  {  return email; }

    public boolean isEmailVerified() {return isEmaildVerified; }

    public String getName() { return name; }

    public String getFamilyName() { return familyName; }

    public String getGivenName() {return givenName; }

    public Map<String, Object> getClaims() { return claims; }
}

