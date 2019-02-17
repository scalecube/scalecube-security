package io.scalecube.security.acl;

import io.scalecube.security.api.AccessControl;
import io.scalecube.security.api.Authenticator;
import io.scalecube.security.api.Authorizer;
import io.scalecube.security.api.Profile;
import io.scalecube.security.jwt.AuthenticationException;
import reactor.core.publisher.Mono;

public class DefaultAccessControl implements AccessControl {
  private final Authenticator authenticator;
  private final Authorizer authorizator;

  public static class Builder {
    private Authenticator authenticator;
    private Authorizer authorizer;

    public Builder authorizer(Authorizer authorizer) {
      this.authorizer = authorizer;
      return this;
    }

    public Builder authenticator(Authenticator authenticator) {
      this.authenticator = authenticator;
      return this;
    }

    public DefaultAccessControl build() {
      return new DefaultAccessControl(this);
    }
  }

  public DefaultAccessControl(Builder builder) {
    this.authenticator = builder.authenticator;
    this.authorizator = builder.authorizer;
  }

  public static DefaultAccessControl.Builder builder() {
    return new DefaultAccessControl.Builder();
  }

  @Override
  public Mono<Profile> check(String token, String resource) {
    return authenticator
        .authenticate(token)
        .switchIfEmpty(
            Mono.error(() -> new AuthenticationException("Authentication Failure", null)))
        .flatMap(profile -> authorizator.authorize(profile, resource));
  }
}
