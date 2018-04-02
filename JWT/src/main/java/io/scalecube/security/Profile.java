package io.scalecube.security;

import java.util.Map;

public class Profile {

    //TODO: check google profile returned from
    //// TODO: do we want to have an optionals here?
    private String id;
    final String tenant;
    private String email;
    private boolean emailVerified;
    private String name;
    private String familyName;
    private String givenName;
    private Map<String, Object> claims;
    ////
    final String userName;
    final String userId;

    public Profile(String userName, String userId, String tenant) {
        this.userName = userName;
        this.userId = userId;
        this.tenant = tenant;
    }

    public String getUserName() {
        return userName;
    }

    public String getUserId() {
        return userId;
    }

    public String getTenant() {
        return tenant;
    }
}

