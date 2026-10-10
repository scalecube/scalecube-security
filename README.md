# scalecube-security

JWT verification against a JWKS endpoint, and service identity (machine-to-machine tokens) on top
of HashiCorp Vault [identity tokens](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token).

| Module | Contents |
|---|---|
| `scalecube-security-jwt` | `Auth0JwtTokenResolver`, `JwksKeyProvider`, `JwtToken` |
| `scalecube-security-vault` | `VaultServiceRolesInstaller`, `VaultServiceTokenSupplier` |

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

`JwksKeyProvider` caches the whole key set for `keyTtl` (default 60s). When a token's `kid` is not
in the cache, the key set is fetched again, at most once per `minRefreshInterval` (default 5s).
Within that interval an unknown `kid` fails straight away, without a remote call. This means
tokens with made-up `kid` values cannot flood the JWKS endpoint.

Only RSA signing keys (`kty: RSA`, `use: sig` or no `use`) are taken from the key set.

### Errors

The returned future fails with `JwtTokenException`, or with its subclass `JwtUnavailableException`
for transient errors that are worth retrying:

- the `kid` is not in the key set (for example, right after key rotation);
- the JWKS endpoint cannot be reached, times out, or does not respond with 200.

`JwtToken.parseToken(token)` only parses a token. It does **not** verify it.

## Vault service identity

A service gets a signed token from Vault for its *service role*. Other services verify it with
`Auth0JwtTokenResolver`, pointed at Vault's JWKS endpoint
`<vault-address>/v1/identity/oidc/.well-known/keys`. The token carries two claims: `role`, and
`permissions` (a comma-separated list).

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
    permissions: [read]
  - role: admin
    permissions: [read, write]
```

| Builder setting | Default |
|---|---|
| `keyAlgorithm` | `RS256` (the only one `Auth0JwtTokenResolver` accepts) |
| `keyRotationPeriod` | `1h` |
| `keyVerificationTtl` | `1h` |
| `roleTtl` (token lifetime) | `1m` |
| `timeout` (whole installation) | `10s` |
| `connectTimeoutSeconds`, `readTimeoutSeconds` (each Vault call) | `10` |

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
`roleNameBuilder`. Each Vault call has a 10s connect timeout and a 10s read timeout by default
(`connectTimeoutSeconds`, `readTimeoutSeconds`).
