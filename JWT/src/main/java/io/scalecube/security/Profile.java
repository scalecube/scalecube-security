package io.scalecube.security;

import java.util.Map;

public class Profile {

    private final Map<String, Object> claims;

    public Profile(Map<String, Object> claims) {
        this.claims = claims;
    }

    public String getUserId() { return fetchFromMap("sub",String.class); }

    public String getTenant() { return fetchFromMap("aud",String.class);} //return tenant; }

    public String getEmail()  {  return fetchFromMap("email",String.class); }//return email; }

    public boolean isEmailVerified() {return fetchFromMap("email_verified",boolean.class); } //return emailVerified; }

    public String getName() { return fetchFromMap("name",String.class); }//return name; }

    public String getFamilyName() { return fetchFromMap("family_name",String.class);}//return familyName; }

    public String getGivenName() {return fetchFromMap("given_name",String.class); }//return givenName; }

    public Map<String, Object> getClaims() { return claims; }

    private <T> T fetchFromMap(String key, Class<T> type) {
        return type.cast(claims.get(key));
    }
}

