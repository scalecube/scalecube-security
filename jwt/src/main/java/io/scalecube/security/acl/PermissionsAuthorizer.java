package io.scalecube.security.acl;

import io.scalecube.security.Profile;
import io.scalecube.security.auth.Authorizer;
import java.security.AccessControlException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import reactor.core.publisher.Mono;

public class PermissionsAuthorizer implements Authorizer {

  public static class Builder {

    Map<String, Set<String>> permissions = new HashMap<>();

    PermissionsAuthorizer.Builder permission(String action, String... subjects) {
      for (String subject : subjects) {
        permissions.computeIfAbsent(action, newAction -> new HashSet()).add(subject);
      }
      return this;
    }

    public Authorizer build() {
      return new PermissionsAuthorizer(this);
    }
  }

  private final Map<String, Set<String>> rolesForAllActions;

  private PermissionsAuthorizer(Builder builder) {
    this.rolesForAllActions = new HashMap<>(builder.permissions.size());
    builder.permissions.forEach(
        (action, subjects) -> {
          this.rolesForAllActions.put(action, new HashSet<>(subjects));
        });
  }

  public static PermissionsAuthorizer.Builder builder() {
    return new Builder();
  }

  private static Set<String> rolesByAction(
      final Map<String, Set<String>> permissionsByAction, String action) {
    return permissionsByAction.getOrDefault(action, Collections.emptySet());
  }

  private static boolean isInRole(Profile profile, Set<String> roles) {
    return roles.contains(profile.claims().getOrDefault("roles", null));
  }

  @Override
  public Mono<Profile> authorize(Profile profile, String action) {
    return Mono.just(profile)
        .filter(p -> isInRole(p, rolesByAction(rolesForAllActions, action)))
        .switchIfEmpty(Mono.error(() -> new AccessControlException("Permission denied")));
  }
}
