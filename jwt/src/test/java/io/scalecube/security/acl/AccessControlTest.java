package io.scalecube.security.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import io.jsonwebtoken.Jwts;
import io.scalecube.security.DefaultJwtAuthenticator;
import io.scalecube.security.JwtKeyResolver;
import io.scalecube.security.acl.AccessControl;
import io.scalecube.security.acl.DefaultAccessControl;
import io.scalecube.security.acl.Permissions;
import io.scalecube.security.api.Authenticator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

public class AccessControlTest {

  private static final String OWNER = "owner";
  private static final String ADMIN = "admin";
  private static final String MEMBER = "member";

  /**
   * an example.
   *
   * @param args ignored
   * @throws NoSuchAlgorithmException when HmacSHA256 is not supported
   */
  @Test
  public void shouldGrantAccess() throws NoSuchAlgorithmException {

    KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
    Key key = kg.generateKey();

    JwtKeyResolver jwtKeyResolver = (m -> "1".equals(m.get("kid")) ? key : null);
    Authenticator authenticator = new DefaultJwtAuthenticator(jwtKeyResolver);

    AccessControl acl =
        DefaultAccessControl.builder()
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
    
    StepVerifier.create(acl.access(token, "repo-create"))
    .assertNext(
        profile -> {
          assertEquals(profile.tenant(), "scalecube");
          assertEquals(profile.claim("roles"), OWNER);
        })
    .verifyComplete();
   
  }
}
