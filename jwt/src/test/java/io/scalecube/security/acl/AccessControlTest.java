package io.scalecube.security.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import io.jsonwebtoken.Jwts;
import io.scalecube.security.DefaultJwtAuthenticator;
import io.scalecube.security.api.Authenticator;
import io.scalecube.security.api.Authorizer;
import java.security.AccessControlException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

public class AccessControlTest {

  // user permissions 
  private static final String RESOURCE_READ = "resource/read";
  private static final String RESOURCE_CREATE = "resource/create";
  private static final String RESOURCE_DELETE = "resource/delete";
  
  // user roles
  private static final String OWNER = "owner";
  private static final String ADMIN = "admin";
  private static final String MEMBER = "member";
  
  private static SecretKey key;
  private static DefaultAccessControl acl;

  @BeforeAll
  public static void setUp() throws Exception {
    key = KeyGenerator.getInstance("HmacSHA256").generateKey();
    Authenticator authenticator =
        new DefaultJwtAuthenticator(m -> "1".equals(m.get("kid")) ? key : null);

    Authorizer permissions =
        Permissions.builder()
            .grant(RESOURCE_DELETE, OWNER)
            .grant(RESOURCE_CREATE, OWNER, ADMIN)
            .grant(RESOURCE_READ, OWNER, ADMIN, MEMBER)
            .build();

    acl =
        DefaultAccessControl.builder()
            .authenticator(authenticator)
            .permissions(permissions)
            .build();
  }

  @Test
  public void shouldGrantAccess() throws NoSuchAlgorithmException {

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

    StepVerifier.create(acl.access(token, RESOURCE_CREATE))
        .assertNext(
            profile -> {
              assertEquals(profile.tenant(), "scalecube");
              assertEquals(profile.claim("roles"), OWNER);
            })
        .verifyComplete();
  }

  @Test
  public void shouldDenyAccess() throws NoSuchAlgorithmException {

    String token =
        Jwts.builder()
            .setHeaderParam("kid", "1")
            .claim("sub", "UID123456789")
            .claim("aud", "scalecube")
            .claim("email", "ron@scalecube.io")
            .claim("name", "ron")
            .claim("roles", MEMBER)
            .signWith(key)
            .compact();

    StepVerifier.create(acl.access(token, RESOURCE_DELETE))
        .expectError(AccessControlException.class)
        .verify();
  }
}