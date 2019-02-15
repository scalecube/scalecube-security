package io.scalecube.security.acl;

import io.jsonwebtoken.Jwts;
import io.scalecube.security.DefaultJwtAuthenticator;
import io.scalecube.security.JwtKeyResolver;
import io.scalecube.security.auth.Authenticator;
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

    KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
    Key key = kg.generateKey();

    JwtKeyResolver jwtKeyResolver = (m -> "1".equals(m.get("kid")) ? key : null);
    Authenticator authenticator = new DefaultJwtAuthenticator(jwtKeyResolver);

    AccessControl acl =
        BaseAccessControl.builder()
        .authenticator(authenticator)
        .permissions(Permissions.builder()
            .grant("repo.delete", OWNER)
            .grant("repo-create", OWNER, ADMIN)
            .grant("repo-read", OWNER, ADMIN, MEMBER)
            .build())
        .build();

    String token =
        Jwts.builder()
            .setHeaderParam("kid", "1")
            .claim("sub", "UID123456789")
            .claim("aud", "scalecube")
            .claim("email", "ron@scalecube.io")
            .claim("name", "ron")
            .claim("roles", OWNER)
            .signWith(key)
            .compact();
    
    acl.access(token, "repo.create").subscribe(System.out::println, System.err::println);
  }
}
