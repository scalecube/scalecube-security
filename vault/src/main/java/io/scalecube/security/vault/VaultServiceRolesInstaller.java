package io.scalecube.security.vault;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
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
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public class VaultServiceRolesInstaller {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceRolesInstaller.class);

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private static final List<Supplier<ServiceRoles>> DEFAULT_SERVICE_ROLES_SOURCES =
      Collections.singletonList(new ResourcesServiceRolesSupplier());

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new YAMLFactory());

  private String vaultAddress;
  private Mono<String> vaultTokenSupplier;
  private Supplier<String> keyNameSupplier;
  private Function<String, String> roleNameBuilder;
  private List<Supplier<ServiceRoles>> serviceRolesSources = DEFAULT_SERVICE_ROLES_SOURCES;
  private String keyAlgorithm = "RS256";
  private String keyRotationPeriod = "1h";
  private String keyVerificationTtl = "1h";
  private String roleTtl = "1m";

  public VaultServiceRolesInstaller() {}

  private VaultServiceRolesInstaller(VaultServiceRolesInstaller other) {
    this.vaultAddress = other.vaultAddress;
    this.vaultTokenSupplier = other.vaultTokenSupplier;
    this.keyNameSupplier = other.keyNameSupplier;
    this.roleNameBuilder = other.roleNameBuilder;
    this.serviceRolesSources = other.serviceRolesSources;
    this.keyAlgorithm = other.keyAlgorithm;
    this.keyRotationPeriod = other.keyRotationPeriod;
    this.keyVerificationTtl = other.keyVerificationTtl;
    this.roleTtl = other.roleTtl;
  }

  private VaultServiceRolesInstaller copy() {
    return new VaultServiceRolesInstaller(this);
  }

  /**
   * Setter for vaultAddress.
   *
   * @param vaultAddress vaultAddress
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller vaultAddress(String vaultAddress) {
    final VaultServiceRolesInstaller c = copy();
    c.vaultAddress = vaultAddress;
    return c;
  }

  /**
   * Setter for vaultTokenSupplier.
   *
   * @param vaultTokenSupplier vaultTokenSupplier
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller vaultTokenSupplier(Mono<String> vaultTokenSupplier) {
    final VaultServiceRolesInstaller c = copy();
    c.vaultTokenSupplier = vaultTokenSupplier;
    return c;
  }

  /**
   * Setter for keyNameSupplier.
   *
   * @param keyNameSupplier keyNameSupplier
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller keyNameSupplier(Supplier<String> keyNameSupplier) {
    final VaultServiceRolesInstaller c = copy();
    c.keyNameSupplier = keyNameSupplier;
    return c;
  }

  /**
   * Setter for roleNameBuilder.
   *
   * @param roleNameBuilder roleNameBuilder
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller roleNameBuilder(Function<String, String> roleNameBuilder) {
    final VaultServiceRolesInstaller c = copy();
    c.roleNameBuilder = roleNameBuilder;
    return c;
  }

  /**
   * Setter for serviceRolesSources.
   *
   * @param serviceRolesSources serviceRolesSources
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller serviceRolesSources(
      List<Supplier<ServiceRoles>> serviceRolesSources) {
    final VaultServiceRolesInstaller c = copy();
    c.serviceRolesSources = serviceRolesSources;
    return c;
  }

  /**
   * Setter for serviceRolesSources.
   *
   * @param serviceRolesSources serviceRolesSources
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller serviceRolesSources(
      Supplier<ServiceRoles>... serviceRolesSources) {
    final VaultServiceRolesInstaller c = copy();
    c.serviceRolesSources = Arrays.asList(serviceRolesSources);
    return c;
  }

  /**
   * Setter for keyAlgorithm.
   *
   * @param keyAlgorithm keyAlgorithm
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller keyAlgorithm(String keyAlgorithm) {
    final VaultServiceRolesInstaller c = copy();
    c.keyAlgorithm = keyAlgorithm;
    return c;
  }

  /**
   * Setter for keyRotationPeriod.
   *
   * @param keyRotationPeriod keyRotationPeriod
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller keyRotationPeriod(String keyRotationPeriod) {
    final VaultServiceRolesInstaller c = copy();
    c.keyRotationPeriod = keyRotationPeriod;
    return c;
  }

  /**
   * Setter for keyVerificationTtl.
   *
   * @param keyVerificationTtl keyVerificationTtl
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller keyVerificationTtl(String keyVerificationTtl) {
    final VaultServiceRolesInstaller c = copy();
    c.keyVerificationTtl = keyVerificationTtl;
    return c;
  }

  /**
   * Setter for roleTtl.
   *
   * @param roleTtl roleTtl
   * @return new instance with applied setting
   */
  public VaultServiceRolesInstaller roleTtl(String roleTtl) {
    final VaultServiceRolesInstaller c = copy();
    c.roleTtl = roleTtl;
    return c;
  }

  /**
   * Reads {@code inputFileName} and builds vault oidc micro-infrastructure (identity roles and
   * keys) to use it for machine-to-machine authentication.
   */
  public Mono<Void> install() {
    return Mono.defer(this::install0)
        .subscribeOn(Schedulers.boundedElastic())
        .doOnError(th -> LOGGER.error("Failed to install serviceRoles, cause: {}", th.toString()));
  }

  private Mono<Void> install0() {
    if (isNullOrNoneOrEmpty(vaultAddress)) {
      LOGGER.debug("Skipping serviceRoles installation, vaultAddress not set");
      return Mono.empty();
    }

    final ServiceRoles serviceRoles = loadServiceRoles();
    if (serviceRoles == null || serviceRoles.roles.isEmpty()) {
      LOGGER.debug("Skipping serviceRoles installation, serviceRoles not set");
      return Mono.empty();
    }

    return Mono.defer(() -> vaultTokenSupplier)
        .doOnSuccess(
            token -> {
              final Rest rest = new Rest().header(VAULT_TOKEN_HEADER, token);

              final String keyName = keyNameSupplier.get();
              createVaultIdentityKey(rest.url(buildVaultIdentityKeyUri(keyName)), keyName);

              for (Role role : serviceRoles.roles) {
                String roleName = roleNameBuilder.apply(role.role);
                createVaultIdentityRole(
                    rest.url(buildVaultIdentityRoleUri(roleName)),
                    keyName,
                    roleName,
                    role.permissions);
              }
            })
        .doOnSuccess(s -> LOGGER.debug("Installed serviceRoles ({})", serviceRoles))
        .then();
  }

  private ServiceRoles loadServiceRoles() {
    if (serviceRolesSources == null) {
      return null;
    }

    for (Supplier<ServiceRoles> serviceRolesSource : serviceRolesSources) {
      try {
        final ServiceRoles serviceRoles = serviceRolesSource.get();
        if (serviceRoles != null) {
          return serviceRoles;
        }
      } catch (Throwable th) {
        LOGGER.warn(
            "Failed to load serviceRoles from {}, cause {}", serviceRolesSource, th.getMessage());
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
      throw Exceptions.propagate(e);
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
      throw Exceptions.propagate(e);
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

    public List<Role> getRoles() {
      return roles;
    }

    public void setRoles(List<Role> roles) {
      this.roles = roles;
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

      public String getRole() {
        return role;
      }

      public void setRole(String role) {
        this.role = role;
      }

      public List<String> getPermissions() {
        return permissions;
      }

      public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
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

    public static final String DEFAULT_FILE = "service_roles.yaml";

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
        return file.exists()
            ? OBJECT_MAPPER.readValue(new FileInputStream(file), ServiceRoles.class)
            : null;
      } catch (Exception e) {
        throw Exceptions.propagate(e);
      }
    }

    @Override
    public String toString() {
      return new StringJoiner(", ", FileServiceRolesSupplier.class.getSimpleName() + "[", "]")
          .add("file='" + file + "'")
          .toString();
    }
  }
}
