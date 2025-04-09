package io.scalecube.security.vault;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultServiceRolesInstaller {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceRolesInstaller.class);

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private static final List<Supplier<ServiceRoles>> DEFAULT_SERVICE_ROLES_SOURCES =
      Collections.singletonList(new ResourcesServiceRolesSupplier());

  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper(new YAMLFactory()).setVisibility(PropertyAccessor.FIELD, Visibility.ANY);

  private final String vaultAddress;
  private final Supplier<CompletableFuture<String>> vaultTokenSupplier;
  private final Supplier<String> keyNameSupplier;
  private final Function<String, String> roleNameBuilder;
  private final List<Supplier<ServiceRoles>> serviceRolesSources;
  private final String keyAlgorithm;
  private final String keyRotationPeriod;
  private final String keyVerificationTtl;
  private final String roleTtl;
  private final long timeout;
  private final TimeUnit timeUnit;

  private VaultServiceRolesInstaller(Builder builder) {
    this.vaultAddress = Objects.requireNonNull(builder.vaultAddress, "vaultAddress");
    this.vaultTokenSupplier =
        Objects.requireNonNull(builder.vaultTokenSupplier, "vaultTokenSupplier");
    this.keyNameSupplier = Objects.requireNonNull(builder.keyNameSupplier, "keyNameSupplier");
    this.roleNameBuilder = Objects.requireNonNull(builder.roleNameBuilder, "roleNameBuilder");
    this.serviceRolesSources =
        Objects.requireNonNull(builder.serviceRolesSources, "serviceRolesSources");
    this.keyAlgorithm = Objects.requireNonNull(builder.keyAlgorithm, "keyAlgorithm");
    this.keyRotationPeriod = Objects.requireNonNull(builder.keyRotationPeriod, "keyRotationPeriod");
    this.keyVerificationTtl =
        Objects.requireNonNull(builder.keyVerificationTtl, "keyVerificationTtl");
    this.roleTtl = Objects.requireNonNull(builder.roleTtl, "roleTtl");
    this.timeout = builder.timeout;
    this.timeUnit = builder.timeUnit;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builds vault oidc micro-infrastructure (identity roles and keys) to use it for
   * machine-to-machine authentication.
   */
  public void install() {
    if (isNullOrNoneOrEmpty(vaultAddress)) {
      LOGGER.debug("Skipping service roles installation, vault address not set");
      return;
    }

    final ServiceRoles serviceRoles = loadServiceRoles();
    if (serviceRoles == null || serviceRoles.roles.isEmpty()) {
      LOGGER.debug("Skipping service roles installation, service roles not set");
      return;
    }

    try {
      vaultTokenSupplier
          .get()
          .thenAcceptAsync(
              token -> {
                final var rest = new Rest().header(VAULT_TOKEN_HEADER, token);
                final var keyName = keyNameSupplier.get();

                createVaultIdentityKey(rest.url(vaultIdentityKeyUri(keyName)), keyName);
                LOGGER.debug("Vault identity key: {}", keyName);

                for (var role : serviceRoles.roles) {
                  final var roleName = roleNameBuilder.apply(role.role);
                  createVaultIdentityRole(
                      rest.url(vaultIdentityRoleUri(roleName)),
                      keyName,
                      role.role,
                      role.permissions);
                  LOGGER.debug("Vault identity role: {}", roleName);
                }

                LOGGER.debug("Installed service roles: {}", serviceRoles);
              })
          .get(timeout, timeUnit);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private ServiceRoles loadServiceRoles() {
    for (Supplier<ServiceRoles> serviceRolesSource : serviceRolesSources) {
      final ServiceRoles serviceRoles = serviceRolesSource.get();
      if (serviceRoles != null) {
        return serviceRoles;
      }
    }

    return null;
  }

  private static void awaitSuccess(int status) {
    if (status != 200 && status != 204) {
      throw new IllegalStateException("Not expected status returned, status=" + status);
    }
  }

  private void createVaultIdentityKey(Rest rest, String keyName) {
    final byte[] body =
        Json.object()
            .add("rotation_period", keyRotationPeriod)
            .add("verification_ttl", keyVerificationTtl)
            .add("allowed_client_ids", "*")
            .add("algorithm", keyAlgorithm)
            .toString()
            .getBytes(StandardCharsets.UTF_8);

    try {
      awaitSuccess(rest.body(body).post().getStatus());
    } catch (RestException e) {
      throw new RuntimeException("Failed to create vault identity key: " + keyName, e);
    }
  }

  private void createVaultIdentityRole(
      Rest rest, String keyName, String roleName, List<String> permissions) {
    final byte[] body =
        Json.object()
            .add("key", keyName)
            .add("template", createTemplate(roleName, permissions))
            .add("ttl", roleTtl)
            .toString()
            .getBytes(StandardCharsets.UTF_8);

    try {
      awaitSuccess(rest.body(body).post().getStatus());
    } catch (RestException e) {
      throw new RuntimeException("Failed to create vault identity role: " + roleName, e);
    }
  }

  private static String createTemplate(String roleName, List<String> permissions) {
    return Base64.getUrlEncoder()
        .encodeToString(
            Json.object()
                .add("role", roleName)
                .add("permissions", String.join(",", permissions))
                .toString()
                .getBytes(StandardCharsets.UTF_8));
  }

  private String vaultIdentityKeyUri(String keyName) {
    return new StringJoiner("/", vaultAddress, "")
        .add("/v1/identity/oidc/key")
        .add(keyName)
        .toString();
  }

  private String vaultIdentityRoleUri(String roleName) {
    return new StringJoiner("/", vaultAddress, "")
        .add("/v1/identity/oidc/role")
        .add(roleName)
        .toString();
  }

  private static boolean isNullOrNoneOrEmpty(String value) {
    return Objects.isNull(value)
        || "none".equalsIgnoreCase(value)
        || "null".equals(value)
        || value.isEmpty();
  }

  public static class ServiceRoles {

    private List<Role> roles;

    public List<Role> roles() {
      return roles;
    }

    public ServiceRoles roles(List<Role> roles) {
      this.roles = roles;
      return this;
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", ServiceRoles.class.getSimpleName() + "[", "]")
          .add("roles=" + roles)
          .toString();
    }

    public static class Role {

      private String role;
      private List<String> permissions;

      public String role() {
        return role;
      }

      public Role role(String role) {
        this.role = role;
        return this;
      }

      public List<String> permissions() {
        return permissions;
      }

      public Role permissions(List<String> permissions) {
        this.permissions = permissions;
        return this;
      }

      @Override
      public String toString() {
        return new StringJoiner(", ", Role.class.getSimpleName() + "[", "]")
            .add("role='" + role + "'")
            .add("permissions=" + permissions)
            .toString();
      }
    }
  }

  public static class ResourcesServiceRolesSupplier implements Supplier<ServiceRoles> {

    public static final String DEFAULT_FILE_NAME = "service-roles.yaml";

    private final String fileName;

    public ResourcesServiceRolesSupplier() {
      this(DEFAULT_FILE_NAME);
    }

    public ResourcesServiceRolesSupplier(String fileName) {
      this.fileName = Objects.requireNonNull(fileName, "fileName");
    }

    @Override
    public ServiceRoles get() {
      try {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(fileName);
        return inputStream != null
            ? OBJECT_MAPPER.readValue(inputStream, ServiceRoles.class)
            : null;
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", ResourcesServiceRolesSupplier.class.getSimpleName() + "[", "]")
          .add("fileName='" + fileName + "'")
          .toString();
    }
  }

  public static class EnvironmentServiceRolesSupplier implements Supplier<ServiceRoles> {

    public static final String DEFAULT_ENV_KEY = "SERVICE_ROLES";

    private final String envKey;

    public EnvironmentServiceRolesSupplier() {
      this(DEFAULT_ENV_KEY);
    }

    public EnvironmentServiceRolesSupplier(String envKey) {
      this.envKey = Objects.requireNonNull(envKey, "envKey");
    }

    @Override
    public ServiceRoles get() {
      try {
        final String value = System.getenv(envKey);
        return value != null
            ? OBJECT_MAPPER.readValue(new StringReader(value), ServiceRoles.class)
            : null;
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public String toString() {
      return new StringJoiner(
              ", ", EnvironmentServiceRolesSupplier.class.getSimpleName() + "[", "]")
          .add("envKey='" + envKey + "'")
          .toString();
    }
  }

  public static class FileServiceRolesSupplier implements Supplier<ServiceRoles> {

    public static final String DEFAULT_FILE = "service-roles.yaml";

    private final String file;

    public FileServiceRolesSupplier() {
      this(DEFAULT_FILE);
    }

    public FileServiceRolesSupplier(String file) {
      this.file = Objects.requireNonNull(file, "file");
    }

    @Override
    public ServiceRoles get() {
      try {
        final File file = new File(this.file);
        if (!file.exists()) {
          return null;
        }
        try (final FileInputStream fis = new FileInputStream(file)) {
          return OBJECT_MAPPER.readValue(fis, ServiceRoles.class);
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", FileServiceRolesSupplier.class.getSimpleName() + "[", "]")
          .add("file='" + file + "'")
          .toString();
    }
  }

  public static class Builder {

    private String vaultAddress;
    private Supplier<CompletableFuture<String>> vaultTokenSupplier;
    private Supplier<String> keyNameSupplier;
    private Function<String, String> roleNameBuilder;
    private List<Supplier<ServiceRoles>> serviceRolesSources = DEFAULT_SERVICE_ROLES_SOURCES;
    private String keyAlgorithm = "RS256";
    private String keyRotationPeriod = "1h";
    private String keyVerificationTtl = "1h";
    private String roleTtl = "1m";
    private long timeout = 10;
    private TimeUnit timeUnit = TimeUnit.SECONDS;

    private Builder() {}

    public Builder vaultAddress(String vaultAddress) {
      this.vaultAddress = vaultAddress;
      return this;
    }

    public Builder vaultTokenSupplier(Supplier<CompletableFuture<String>> vaultTokenSupplier) {
      this.vaultTokenSupplier = vaultTokenSupplier;
      return this;
    }

    public Builder keyNameSupplier(Supplier<String> keyNameSupplier) {
      this.keyNameSupplier = keyNameSupplier;
      return this;
    }

    public Builder roleNameBuilder(Function<String, String> roleNameBuilder) {
      this.roleNameBuilder = roleNameBuilder;
      return this;
    }

    public Builder serviceRolesSources(List<Supplier<ServiceRoles>> serviceRolesSources) {
      this.serviceRolesSources = serviceRolesSources;
      return this;
    }

    public Builder keyAlgorithm(String keyAlgorithm) {
      this.keyAlgorithm = keyAlgorithm;
      return this;
    }

    public Builder keyRotationPeriod(String keyRotationPeriod) {
      this.keyRotationPeriod = keyRotationPeriod;
      return this;
    }

    public Builder keyVerificationTtl(String keyVerificationTtl) {
      this.keyVerificationTtl = keyVerificationTtl;
      return this;
    }

    public Builder roleTtl(String roleTtl) {
      this.roleTtl = roleTtl;
      return this;
    }

    public Builder timeout(long timeout, TimeUnit timeUnit) {
      this.timeout = timeout;
      this.timeUnit = timeUnit;
      return this;
    }

    public VaultServiceRolesInstaller build() {
      return new VaultServiceRolesInstaller(this);
    }
  }
}
