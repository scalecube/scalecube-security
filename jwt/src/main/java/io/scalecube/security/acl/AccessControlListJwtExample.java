package io.scalecube.security.acl;

import io.jsonwebtoken.Jwts;
import io.scalecube.security.DefaultJwtAuthenticator;
import io.scalecube.security.JwtKeyResolver;
import io.scalecube.security.auth.AccessControl;
import io.scalecube.security.auth.Authenticator;
import io.scalecube.security.auth.Authorizer;
import io.scalecube.security.auth.BaseAccessControl;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;

public class AccessControlListJwtExample {

  private static final String OWNER = "owner";
  private static final String ADMIN = "admin";
  private static final String MEMBER = "member";

  /**
   * an example.
   *
   * @param args ignored
   * @throws NoSuchAlgorithmException when HmacSHA256 is not supported
   */
  public static void main(String[] args) throws NoSuchAlgorithmException {

    Authorizer permissions =
        Permissions.builder()
            .grant("repo.delete", OWNER)
            .grant("repo-create", OWNER, ADMIN)
            .grant("repo-read", OWNER, ADMIN, MEMBER)
            .build();

    KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
    Key key = kg.generateKey();

    JwtKeyResolver jwtKeyResolver = (m -> "1".equals(m.get("kid")) ? key : null);
    Authenticator authenticator = new DefaultJwtAuthenticator(jwtKeyResolver);

    AccessControl control =
        BaseAccessControl.builder()
        .authenticator(authenticator)
        .permissions(permissions)
        .build();

    String token =
        Jwts.builder()
            .setHeaderParam("kid", "1")
            .claim("sub", "UID123456789")
            .claim("aud", "scalecube")
            .claim("email", "myemail@example.com")
            .claim("name", "ronen")
            .claim("roles", OWNER)
            .signWith(key)
            .compact();
    
    control.tryAccess(token, "repo.create").subscribe(System.out::println, System.err::println);
  }
}
