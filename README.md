# scalecube-security

# JWT authentication basic usage

Given a JWT we would like to authenticate it and extract its claims:

Generating JWT for example:

``` java
String hmacSecret = "secert";

String token = Jwts.builder().setAudience("anAudience")
                .setSubject("aSubject")
                .signWith(SignatureAlgorithm.HS256, hmacSecret.getBytes())
                .compact();
```

Authenticating the JWT:
``` java
JwtAuthenticator authenticator = new JwtAuthenticatorImpl
                .Builder()
                .keyResolver(map -> Optional.of(new SecretKeySpec(hmacSecret.getBytes(), "HMACSHA256")))
                .build();
                
Profile profile = authenticator.authenticate(token)
```
