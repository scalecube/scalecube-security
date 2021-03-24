package io.scalecube.security.tokens.jwt;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.scheduler.VirtualTimeScheduler;

class JwtTokenResolverTests {

  private static final Map<String, Object> BODY = Collections.singletonMap("aud", "aud");

  @Test
  void testTokenResolver() throws Exception {
    JwtTokenWithKey tokenWithKey = new JwtTokenWithKey("token-and-pubkey.properties");

    JwtTokenParser tokenParser = Mockito.mock(JwtTokenParser.class);
    Mockito.when(tokenParser.parseToken())
        .thenReturn(new JwtToken(Collections.singletonMap("kid", tokenWithKey.kid), BODY));
    Mockito.when(tokenParser.verifyToken(tokenWithKey.key))
        .thenReturn(Mockito.mock(JwtToken.class));

    JwtTokenParserFactory tokenParserFactory = Mockito.mock(JwtTokenParserFactory.class);
    Mockito.when(tokenParserFactory.newParser(ArgumentMatchers.anyString()))
        .thenReturn(tokenParser);

    KeyProvider keyProvider = Mockito.mock(KeyProvider.class);
    Mockito.when(keyProvider.findKey(tokenWithKey.kid)).thenReturn(Mono.just(tokenWithKey.key));

    JwtTokenResolverImpl tokenResolver =
        new JwtTokenResolverImpl()
            .keyProvider(keyProvider)
            .tokenParserFactory(tokenParserFactory)
            .scheduler(VirtualTimeScheduler.create())
            .cleanupInterval(Duration.ofSeconds(3));

    // N times call resolve
    StepVerifier.create(tokenResolver.resolve(tokenWithKey.token).repeat(3))
        .expectNextCount(3)
        .thenCancel()
        .verify();

    // check caching, must have been called 1 time
    Mockito.verify(keyProvider, Mockito.times(1)).findKey(tokenWithKey.kid);
  }

  @Test
  void testTokenResolverWithRotatingKey() throws Exception {
    JwtTokenWithKey tokenWithKey = new JwtTokenWithKey("token-and-pubkey.properties");
    JwtTokenWithKey tokenWithKeyAfterRotation =
        new JwtTokenWithKey("token-and-pubkey.after-rotation.properties");

    JwtTokenParser tokenParser = Mockito.mock(JwtTokenParser.class);
    Mockito.when(tokenParser.parseToken())
        .thenReturn(new JwtToken(Collections.singletonMap("kid", tokenWithKey.kid), BODY))
        .thenReturn(
            new JwtToken(Collections.singletonMap("kid", tokenWithKeyAfterRotation.kid), BODY));

    Mockito.when(tokenParser.verifyToken(tokenWithKey.key))
        .thenReturn(Mockito.mock(JwtToken.class));
    Mockito.when(tokenParser.verifyToken(tokenWithKeyAfterRotation.key))
        .thenReturn(Mockito.mock(JwtToken.class));

    JwtTokenParserFactory tokenParserFactory = Mockito.mock(JwtTokenParserFactory.class);
    Mockito.when(tokenParserFactory.newParser(ArgumentMatchers.anyString()))
        .thenReturn(tokenParser);

    KeyProvider keyProvider = Mockito.mock(KeyProvider.class);
    Mockito.when(keyProvider.findKey(tokenWithKey.kid)).thenReturn(Mono.just(tokenWithKey.key));
    Mockito.when(keyProvider.findKey(tokenWithKeyAfterRotation.kid))
        .thenReturn(Mono.just(tokenWithKeyAfterRotation.key));

    JwtTokenResolverImpl tokenResolver =
        new JwtTokenResolverImpl()
            .keyProvider(keyProvider)
            .tokenParserFactory(tokenParserFactory)
            .scheduler(VirtualTimeScheduler.create())
            .cleanupInterval(Duration.ofSeconds(3));

    // Call normal token first
    StepVerifier.create(tokenResolver.resolve(tokenWithKey.token))
        .expectNextCount(1)
        .expectComplete()
        .verify();

    // Call token after rotation (call N times)
    StepVerifier.create(tokenResolver.resolve(tokenWithKeyAfterRotation.token).repeat(3))
        .expectNextCount(3)
        .thenCancel()
        .verify();

    // in total must have been called 2 times
    Mockito.verify(keyProvider, Mockito.times(1)).findKey(tokenWithKey.kid);
    Mockito.verify(keyProvider, Mockito.times(1)).findKey(tokenWithKeyAfterRotation.kid);
  }

  @Test
  void testTokenResolverWithWrongKey() throws Exception {
    JwtTokenWithKey tokenWithWrongKey = new JwtTokenWithKey("token-and-wrong-pubkey.properties");

    JwtTokenParser tokenParser = Mockito.mock(JwtTokenParser.class);
    Mockito.when(tokenParser.parseToken())
        .thenReturn(new JwtToken(Collections.singletonMap("kid", tokenWithWrongKey.kid), BODY));
    Mockito.when(tokenParser.verifyToken(tokenWithWrongKey.key)).thenThrow(RuntimeException.class);

    JwtTokenParserFactory tokenParserFactory = Mockito.mock(JwtTokenParserFactory.class);
    Mockito.when(tokenParserFactory.newParser(ArgumentMatchers.anyString()))
        .thenReturn(tokenParser);

    KeyProvider keyProvider = Mockito.mock(KeyProvider.class);
    Mockito.when(keyProvider.findKey(tokenWithWrongKey.kid))
        .thenReturn(Mono.just(tokenWithWrongKey.key));

    JwtTokenResolverImpl tokenResolver =
        new JwtTokenResolverImpl()
            .keyProvider(keyProvider)
            .tokenParserFactory(tokenParserFactory)
            .scheduler(VirtualTimeScheduler.create())
            .cleanupInterval(Duration.ofSeconds(3));

    // Must fail (retry N times)
    StepVerifier.create(tokenResolver.resolve(tokenWithWrongKey.token).retry(1))
        .expectError()
        .verify();

    // failed resolution not stored => keyProvider must have been called 2 times
    Mockito.verify(keyProvider, Mockito.times(2)).findKey(tokenWithWrongKey.kid);
  }

  @Test
  void testTokenResolverWhenKeyProviderFailing() throws Exception {
    JwtTokenWithKey tokenWithKey = new JwtTokenWithKey("token-and-pubkey.properties");

    JwtTokenParser tokenParser = Mockito.mock(JwtTokenParser.class);
    Mockito.when(tokenParser.parseToken())
        .thenReturn(new JwtToken(Collections.singletonMap("kid", tokenWithKey.kid), BODY));
    Mockito.when(tokenParser.verifyToken(tokenWithKey.key))
        .thenReturn(Mockito.mock(JwtToken.class));

    JwtTokenParserFactory tokenParserFactory = Mockito.mock(JwtTokenParserFactory.class);
    Mockito.when(tokenParserFactory.newParser(ArgumentMatchers.anyString()))
        .thenReturn(tokenParser);

    KeyProvider keyProvider = Mockito.mock(KeyProvider.class);
    Mockito.when(keyProvider.findKey(tokenWithKey.kid)).thenThrow(RuntimeException.class);

    JwtTokenResolverImpl tokenResolver =
        new JwtTokenResolverImpl()
            .keyProvider(keyProvider)
            .tokenParserFactory(tokenParserFactory)
            .scheduler(VirtualTimeScheduler.create())
            .cleanupInterval(Duration.ofSeconds(3));

    // Must fail with "hola" (retry N times)
    StepVerifier.create(tokenResolver.resolve(tokenWithKey.token).retry(1)).expectError().verify();

    // failed resolution not stored => keyProvider must have been called 2 times
    Mockito.verify(keyProvider, Mockito.times(2)).findKey(tokenWithKey.kid);
  }
}
