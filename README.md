# scalecube-security

JWT verification against a JWKS endpoint, and service identity (machine-to-machine tokens) on top
of HashiCorp
Vault [identity tokens](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token).

| Module                     | Contents                                                  |
|----------------------------|-----------------------------------------------------------|
| `scalecube-security-jwt`   | `Auth0JwtTokenResolver`, `JwksKeyProvider`, `JwtToken`    |
| `scalecube-security-vault` | `VaultServiceRolesInstaller`, `VaultServiceTokenSupplier` |

```xml
<dependency>
  <groupId>io.scalecube</groupId>
  <artifactId>scalecube-security-jwt</artifactId> <!-- or scalecube-security-vault -->
  <version>${scalecube-security.version}</version>
</dependency>
```

## JWT verification

```java
JwtTokenResolver tokenResolver =
    Auth0JwtTokenResolver.builder()
        .keyProvider(
            JwksKeyProvider.builder()
                .jwksUri("https://issuer/.well-known/jwks.json")
                .build())
        .issuer("https://issuer/") // optional
        .audience("my-api") // optional
        .build();

CompletableFuture<JwtToken> result = tokenResolver.resolveToken(token);
```

`resolveToken` verifies the signature and the time claims (`exp`, `nbf`, `iat`), and, if
configured, `iss` and `aud`. On success it returns the token header and claims as maps.

- Only `RS256` is supported.
- `issuer` and `audience` are optional. Set them whenever they are known. Vault identity tokens
  carry a per-role `aud` (the role's client id), and their `iss` is derived from Vault's
  `api_addr`, so the verifier often cannot know them in advance.
- Verification runs on the `executor` set in the builder (default `ForkJoinPool.commonPool()`).
  It blocks only while the JWKS is being fetched.

### Key caching

`JwksKeyProvider` caches the whole key set for `keyTtl` (in millis, default 60000). The key set is
fetched again when a token's `kid` is not in the cache, or when the cached key set has expired.
Fetches happen on the calling thread, at most once per `minRefreshInterval` (default 5s).

- Unknown `kid`: the caller waits for the fetch. Within `minRefreshInterval` it fails straight
  away without a remote call, so tokens with made-up `kid` values cannot flood the JWKS endpoint.
- Expired key set: one caller fetches, the others keep using the expired keys. Expired keys are
  also used when the fetch is rate-limited by `minRefreshInterval`, or fails. So verification
  keeps working while the JWKS endpoint is down, at the cost of accepting a key that the issuer
  has removed until the next successful fetch.

Invalid keys in the key set are skipped with a warning.

| Builder setting                    | Default                                |
|------------------------------------|----------------------------------------|
| `connectTimeout`, `requestTimeout` | `10s`                                  |
| `keyTtl`                           | `60000` (millis)                       |
| `minRefreshInterval`               | `5s`                                   |
| `httpClient`                       | new `HttpClient` with `connectTimeout` |

Only RSA signing keys (`kty: RSA`, `use: sig` or no `use`) are taken from the key set.

### Errors

The returned future fails with `JwtTokenException`, or with its subclass `JwtUnavailableException`
for transient errors that are worth retrying:

- the `kid` is not in the key set (for example, right after key rotation);
- the JWKS endpoint cannot be reached, times out, or does not respond with 200.

Tokens without a `kid` header are rejected (`JwtTokenException`).

`JwtToken.parseToken(token)` only parses a token. It does **not** verify it.

## Vault service identity

A service gets a signed token from Vault for its *service role*. Other services verify it with
`Auth0JwtTokenResolver`, pointed at Vault's JWKS endpoint
`<vault-address>/v1/identity/oidc/.well-known/keys` (no Vault token needed). Besides the standard
claims, the token carries `role` and `permissions` (a comma-separated list).

The Vault token passed in `vaultTokenSupplier` needs a policy that allows:

- for the installer: `create`/`update` on `identity/oidc/key/<key>` and `identity/oidc/role/<role>`;
- for the token supplier: `read` on `identity/oidc/token/<role>`. Vault issues identity tokens
  only to tokens that belong to an identity entity, i.e. obtained through an auth method login
  (Kubernetes, AppRole, userpass, ...), not the root token.

### Installing service roles

`VaultServiceRolesInstaller` creates (or updates) a Vault identity key and one identity role per
service role:

```java
VaultServiceRolesInstaller.builder()
    .vaultAddress("http://vault:8200")
    .vaultTokenSupplier(() -> CompletableFuture.completedFuture(vaultToken))
    .keyNameSupplier(() -> "identity-key")
    .roleNameBuilder(role -> "my-service." + role)
    .build()
    .install();
```

Service roles are read from the first `serviceRolesSources` entry that returns a result. The
default source is the classpath resource `service-roles.yaml`. `FileServiceRolesSupplier` and
`EnvironmentServiceRolesSupplier` are also available.

```yaml
roles:
  - role: reader
    permissions: [ read ]
  - role: admin
    permissions: [ read, write ]
```

| Builder setting                | Default                                                |
|--------------------------------|--------------------------------------------------------|
| `keyAlgorithm`                 | `RS256` (the only one `Auth0JwtTokenResolver` accepts) |
| `keyRotationPeriod`            | `1h`                                                   |
| `keyVerificationTtl`           | `1h`                                                   |
| `roleTtl` (token lifetime)     | `1m`                                                   |
| `timeout` (whole installation) | `10s`                                                  |

`roleTtl` must not be longer than `keyVerificationTtl`: Vault (since 1.8.1) rejects such a role
with `400`.

If `vaultAddress` is empty, `none` or `null` (the string), installation is skipped.

### Getting a service token

```java
CompletableFuture<String> serviceToken =
    VaultServiceTokenSupplier.builder()
        .vaultAddress("http://vault:8200")
        .vaultTokenSupplier(() -> CompletableFuture.completedFuture(vaultToken))
        .serviceRole("reader")
        .serviceTokenNameBuilder((role, tags) -> "my-service." + role)
        .build()
        .getToken(Map.of());
```

`serviceTokenNameBuilder` must produce the same Vault role name as the installer's
`roleNameBuilder`.

### Vault HTTP calls

Both classes call the [Vault HTTP API](https://developer.hashicorp.com/vault/api-docs) with the JDK
`HttpClient`, following the API reference rather than a particular Vault version.

- Every request sends `X-Vault-Token` and `X-Vault-Request: true`.
- `200` and `204` are success. Any other status fails with `VaultRequestException`, which carries
  the status code and Vault's error messages.
- Redirects (`307` from a standby node, when request forwarding is off) are followed, keeping the
  method, body and Vault token, to whatever host the Vault node names (its `api_addr`). The JDK
  client never follows a redirect from `https` to `http`.
- A trailing `/` in `vaultAddress` is ignored, and an address with a path prefix
  (`https://host/vault`) is supported; a query or fragment is rejected. Key and role names must
  not contain `/` or end with `.`.
- No retries: retrying is up to the caller.

| Builder setting (both classes) | Default                                                     |
|--------------------------------|-------------------------------------------------------------|
| `connectTimeout`               | `10s`                                                       |
| `requestTimeout`               | `10s` (each Vault call)                                     |
| `httpClient`                   | new `HttpClient` with `connectTimeout`, following redirects |

### Supported Vault versions

Compatibility is guaranteed for two Vault versions: the oldest release still
[supported by HashiCorp](https://developer.hashicorp.com/vault/docs/enterprise/lts), and the
latest release. The exact versions are the CI matrix in `.github/workflows/branch-ci.yml`, run on
every push. When a version leaves HashiCorp support it is dropped, and the latest entry moves with
new releases. CI also runs `hashicorp/vault:latest` without failing the build, as an early warning.
Other versions are likely to work but are not guaranteed.

To run the integration tests against a given Vault version:
`mvn verify -Dvault.image=hashicorp/vault:<version>` (default: the latest guaranteed version).
