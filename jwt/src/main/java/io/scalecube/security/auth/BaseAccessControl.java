package io.scalecube.security.auth;

import io.scalecube.security.AuthenticationException;
import io.scalecube.security.Profile;
import reactor.core.publisher.Mono;

public class BaseAccessControl implements AccessControl {
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

    public BaseAccessControl build() {
      return new BaseAccessControl(this);
    }
  }

  public BaseAccessControl(Builder builder) {
    this.authenticator = builder.authenticator;
    this.authorizator = builder.authorizer;
  }

  public static BaseAccessControl.Builder builder() {
    return new BaseAccessControl.Builder();
  }

  @Override
  public Mono<Profile> tryAccess(String identity, String action) {
    return authenticator
        .authenticate(identity)
        .switchIfEmpty(
            Mono.error(() -> new AuthenticationException("Authentication Failure", null)))
        .flatMap(profile -> authorizator.authorize(profile, action));
  }
}
