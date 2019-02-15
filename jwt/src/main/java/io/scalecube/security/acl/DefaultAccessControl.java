package io.scalecube.security.acl;

import io.scalecube.security.AuthenticationException;
import io.scalecube.security.api.Authenticator;
import io.scalecube.security.api.Authorizer;
import io.scalecube.security.api.Profile;
import reactor.core.publisher.Mono;

public class DefaultAccessControl implements AccessControl {
  Authenticator authenticator;
  Authorizer authorizator;

  public static class Builder {
    Authenticator authenticator;
    Authorizer authorizer;

    public Builder permissions(Authorizer authorizer) {
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
  public Mono<Profile> access(String identity, String action) {
    return authenticator
        .authenticate(identity)
        .switchIfEmpty(
            Mono.error(() -> new AuthenticationException("Authentication Failure", null)))
        .flatMap(profile -> authorizator.authorize(profile, action));
  }
}
