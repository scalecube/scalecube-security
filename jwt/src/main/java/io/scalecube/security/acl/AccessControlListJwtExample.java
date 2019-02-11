package io.scalecube.security.acl;

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
  
  /**
   * an example
   *
   * @param args
   * @throws NoSuchAlgorithmException
   */
  public static void main(String[] args) throws NoSuchAlgorithmException {

    Authorizer permissions =
        PermissionsAuthorizer.builder()
            .permission("repo.create", "owner", "admin")
            .permission("blah", "owner", "admin", "member")
            .permission("repo.remove", "owner")
            .build();

    KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
    Key key = kg.generateKey();

    JwtKeyResolver jwtKeyResolver = (m -> key);

    Authenticator authenticator = new DefaultJwtAuthenticator(jwtKeyResolver);

    //
    //    Mono<Key> monoKey = Mono.create(service -> {
    //      try {
    //        Thread.sleep(100);
    //      } catch (InterruptedException ignoredException) {
    //        // TODO Auto-generated catch block
    //        ignoredException.printStackTrace();
    //      };
    //      service.success(key);
    //    });
    //
    //    AsyncJwtKeyResolver asyncJwtKeyResolver = kid-> monoKey;
    //    Authenticator authenticator1 = new AsyncJwtAuthenticator(asyncJwtKeyResolver);

    AccessControl control =
        BaseAccessControl.builder().authenticator(authenticator).authorizer(permissions).build();

    String token = "{header:1}.{claims..'ronen'.}.hash";
    control.tryAccess(token, "repo.create").subscribe(System.out::println, System.err::println);
  }
}
