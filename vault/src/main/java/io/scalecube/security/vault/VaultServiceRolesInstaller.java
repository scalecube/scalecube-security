package io.scalecube.security.vault;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.scalecube.security.vault.VaultServiceRolesInstaller.ServiceRoles.Role;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;
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
  private final Supplier<String> vaultTokenSupplier;
  private final Supplier<String> keyNameSupplier;
  private final Function<String, String> roleNameBuilder;
  private final List<Supplier<ServiceRoles>> serviceRolesSources;
  private final String keyAlgorithm;
  private final String keyRotationPeriod;
  private final String keyVerificationTtl;
  private final String roleTtl;

  private VaultServiceRolesInstaller(Builder builder) {
    this.vaultAddress = builder.vaultAddress;
    this.vaultTokenSupplier = builder.vaultTokenSupplier;
    this.keyNameSupplier = builder.keyNameSupplier;
    this.roleNameBuilder = builder.roleNameBuilder;
    this.serviceRolesSources = builder.serviceRolesSources;
    this.keyAlgorithm = builder.keyAlgorithm;
    this.keyRotationPeriod = builder.keyRotationPeriod;
    this.keyVerificationTtl = builder.keyVerificationTtl;
    this.roleTtl = builder.roleTtl;
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
      LOGGER.debug("Skipping serviceRoles installation, vaultAddress not set");
      return;
    }

    final ServiceRoles serviceRoles = loadServiceRoles();
    if (serviceRoles == null || serviceRoles.roles.isEmpty()) {
      LOGGER.debug("Skipping serviceRoles installation, serviceRoles not set");
      return;
    }

    final String token = vaultTokenSupplier.get();
    final Rest rest = new Rest().header(VAULT_TOKEN_HEADER, token);

    final String keyName = keyNameSupplier.get();
    createVaultIdentityKey(rest.url(buildVaultIdentityKeyUri(keyName)), keyName);

    for (Role role : serviceRoles.roles) {
      String roleName = roleNameBuilder.apply(role.role);
      createVaultIdentityRole(
          rest.url(buildVaultIdentityRoleUri(roleName)), keyName, roleName, role.permissions);
    }

    LOGGER.debug("Installed serviceRoles ({})", serviceRoles);
  }

  private ServiceRoles loadServiceRoles() {
    if (serviceRolesSources == null) {
      return null;
    }

    for (Supplier<ServiceRoles> serviceRolesSource : serviceRolesSources) {
      final ServiceRoles serviceRoles = serviceRolesSource.get();
      if (serviceRoles != null) {
        return serviceRoles;
      }
    }

    return null;
  }

  private static void verifyOk(int status, String operation) {
    if (status != 200 && status != 204) {
      LOGGER.error("Not expected status ({}) returned on [{}]", status, operation);
      throw new IllegalStateException("Not expected status returned, status=" + status);
    }
  }

  private void createVaultIdentityKey(Rest rest, String keyName) {
    LOGGER.debug("[createVaultIdentityKey] {}", keyName);

    byte[] body =
        Json.object()
            .add("rotation_period", keyRotationPeriod)
            .add("verification_ttl", keyVerificationTtl)
            .add("allowed_client_ids", "*")
            .add("algorithm", keyAlgorithm)
            .toString()
            .getBytes();

    try {
      verifyOk(rest.body(body).post().getStatus(), "createVaultIdentityKey");
    } catch (RestException e) {
      throw new RuntimeException(e);
    }
  }

  private void createVaultIdentityRole(
      Rest rest, String keyName, String roleName, List<String> permissions) {
    LOGGER.debug("[createVaultIdentityRole] {}", roleName);

    byte[] body =
        Json.object()
            .add("key", keyName)
            .add("template", createTemplate(permissions))
            .add("ttl", roleTtl)
            .toString()
            .getBytes();

    try {
      verifyOk(rest.body(body).post().getStatus(), "createVaultIdentityRole");
    } catch (RestException e) {
      throw new RuntimeException(e);
    }
  }

  private static String createTemplate(List<String> permissions) {
    return Base64.getUrlEncoder()
        .encodeToString(
            Json.object().add("permissions", String.join(",", permissions)).toString().getBytes());
  }

  private String buildVaultIdentityKeyUri(String keyName) {
    return new StringJoiner("/", vaultAddress, "")
        .add("/v1/identity/oidc/key")
        .add(keyName)
        .toString();
  }

  private String buildVaultIdentityRoleUri(String roleName) {
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
      } catch (Exception e) {
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
    private Supplier<String> vaultTokenSupplier;
    private Supplier<String> keyNameSupplier;
    private Function<String, String> roleNameBuilder;
    private List<Supplier<ServiceRoles>> serviceRolesSources = DEFAULT_SERVICE_ROLES_SOURCES;
    private String keyAlgorithm = "RS256";
    private String keyRotationPeriod = "1h";
    private String keyVerificationTtl = "1h";
    private String roleTtl = "1m";

    private Builder() {}

    public Builder vaultAddress(String vaultAddress) {
      this.vaultAddress = vaultAddress;
      return this;
    }

    public Builder vaultTokenSupplier(Supplier<String> vaultTokenSupplier) {
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

    public Builder serviceRolesSources(Supplier<ServiceRoles>... serviceRolesSources) {
      this.serviceRolesSources = Arrays.asList(serviceRolesSources);
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

    public VaultServiceRolesInstaller build() {
      return new VaultServiceRolesInstaller(this);
    }
  }
}
