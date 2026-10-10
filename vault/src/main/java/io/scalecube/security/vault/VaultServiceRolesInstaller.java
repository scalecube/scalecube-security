package io.scalecube.security.vault;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultServiceRolesInstaller {

  private static final Logger LOGGER = LoggerFactory.getLogger(VaultServiceRolesInstaller.class);

  private static final List<Supplier<ServiceRoles>> DEFAULT_SERVICE_ROLES_SOURCES =
      Collections.singletonList(new ResourcesServiceRolesSupplier());

  private static final ObjectMapper OBJECT_MAPPER =
      new ObjectMapper(new YAMLFactory()).setVisibility(PropertyAccessor.FIELD, Visibility.ANY);

  private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

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
  private final VaultClient vaultClient;

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
    this.vaultClient =
        isNullOrNoneOrEmpty(vaultAddress)
            ? null
            : new VaultClient(
                vaultAddress,
                builder.httpClient != null
                    ? builder.httpClient
                    : VaultClient.newHttpClient(builder.connectTimeout),
                builder.requestTimeout);
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
    if (serviceRoles == null || serviceRoles.roles == null || serviceRoles.roles.isEmpty()) {
      LOGGER.debug("Skipping service roles installation, service roles not set");
      return;
    }

    for (var role : serviceRoles.roles) {
      if (role == null || role.role == null || role.role.isEmpty()) {
        throw new IllegalArgumentException("Invalid service role: " + role);
      }
    }

    final var keyName = keyNameSupplier.get();
    final var installation =
        vaultTokenSupplier
            .get()
            .thenCompose(
                token -> {
                  CompletableFuture<?> future =
                      vaultClient
                          .post(token, keyBody(), "identity", "oidc", "key", keyName)
                          .thenRun(() -> LOGGER.debug("Vault identity key: {}", keyName));

                  for (var role : serviceRoles.roles) {
                    final var roleName = roleNameBuilder.apply(role.role);
                    future =
                        future
                            .thenCompose(
                                v ->
                                    vaultClient.post(
                                        token,
                                        roleBody(keyName, role.role, role.permissions),
                                        "identity",
                                        "oidc",
                                        "role",
                                        roleName))
                            .thenRun(() -> LOGGER.debug("Vault identity role: {}", roleName));
                  }
                  return future;
                });

    try {
      installation.get(timeout, timeUnit);
      LOGGER.debug("Installed service roles: {}", serviceRoles);
    } catch (ExecutionException e) {
      throw new RuntimeException("Failed to install service roles", e.getCause());
    } catch (TimeoutException e) {
      // Stops remaining steps; an in-flight http request is bounded by requestTimeout instead
      installation.cancel(true);
      throw new RuntimeException("Failed to install service roles, timeout", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException("Interrupted while installing service roles", e);
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

  // https://developer.hashicorp.com/vault/api-docs/secret/identity/tokens#create-a-named-key
  private Map<String, Object> keyBody() {
    return Map.of(
        "rotation_period", keyRotationPeriod,
        "verification_ttl", keyVerificationTtl,
        "allowed_client_ids", List.of("*"),
        "algorithm", keyAlgorithm);
  }

  // https://developer.hashicorp.com/vault/api-docs/secret/identity/tokens#create-or-update-a-role
  private Map<String, Object> roleBody(String keyName, String roleName, List<String> permissions) {
    return Map.of("key", keyName, "template", template(roleName, permissions), "ttl", roleTtl);
  }

  // Template is a json string (base64 is also accepted by vault, but not needed)
  private static String template(String roleName, List<String> permissions) {
    try {
      return JSON_MAPPER.writeValueAsString(
          Map.of(
              "role",
              roleName,
              "permissions",
              permissions != null ? String.join(",", permissions) : ""));
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException(e);
    }
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
      final ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
      try (InputStream inputStream = classLoader.getResourceAsStream(fileName)) {
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

    private final Properties properties;
    private final String envKey;

    public EnvironmentServiceRolesSupplier(Properties properties) {
      this(properties, DEFAULT_ENV_KEY);
    }

    /**
     * Constructor.
     *
     * @param properties properties
     * @param envKey variable name holding service roles yaml
     */
    public EnvironmentServiceRolesSupplier(Properties properties, String envKey) {
      this.properties = Objects.requireNonNull(properties, "properties");
      this.envKey = Objects.requireNonNull(envKey, "envKey");
    }

    @Override
    public ServiceRoles get() {
      try {
        final String value = properties.getProperty(envKey);
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
    private Duration connectTimeout = Duration.ofSeconds(10);
    private Duration requestTimeout = Duration.ofSeconds(10);
    private HttpClient httpClient;

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

    /**
     * Setter for {@code connectTimeout} of vault http calls. Ignored if {@code httpClient} is set.
     *
     * @param connectTimeout connectTimeout (optional)
     * @return this
     */
    public Builder connectTimeout(Duration connectTimeout) {
      this.connectTimeout = connectTimeout;
      return this;
    }

    /**
     * Setter for {@code requestTimeout} of each vault http call.
     *
     * @param requestTimeout requestTimeout (optional)
     * @return this
     */
    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    /**
     * Setter for optional {@link HttpClient}. It should follow redirects ({@link
     * HttpClient.Redirect#NORMAL}), as vault standby nodes may redirect to the active node.
     *
     * @param httpClient httpClient
     * @return this
     */
    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = httpClient;
      return this;
    }

    public VaultServiceRolesInstaller build() {
      return new VaultServiceRolesInstaller(this);
    }
  }
}
