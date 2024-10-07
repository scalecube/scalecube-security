package io.scalecube.security.tokens.jwt;

import io.scalecube.security.tokens.jwt.jsonwebtoken.JsonwebtokenParserFactory;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.Key;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

public final class JwtTokenResolverImpl implements JwtTokenResolver {

  private static final Logger LOGGER = System.getLogger(JwtTokenResolver.class.getName());

  private KeyProvider keyProvider;
  private JwtTokenParserFactory tokenParserFactory = new JsonwebtokenParserFactory();
  private Scheduler scheduler = Schedulers.boundedElastic();
  private Duration cleanupInterval = Duration.ofSeconds(60);

  private final Map<String, Mono<Key>> keyResolutions = new ConcurrentHashMap<>();

  public JwtTokenResolverImpl() {}

  private JwtTokenResolverImpl(JwtTokenResolverImpl other) {
    this.keyProvider = other.keyProvider;
    this.tokenParserFactory = other.tokenParserFactory;
    this.scheduler = other.scheduler;
    this.cleanupInterval = other.cleanupInterval;
  }

  /**
   * Setter for keyProvider.
   *
   * @param keyProvider keyProvider
   * @return new instance with applied setting
   */
  public JwtTokenResolverImpl keyProvider(KeyProvider keyProvider) {
    final JwtTokenResolverImpl c = copy();
    c.keyProvider = keyProvider;
    return c;
  }

  /**
   * Setter for tokenParserFactory.
   *
   * @param tokenParserFactory tokenParserFactory
   * @return new instance with applied setting
   */
  public JwtTokenResolverImpl tokenParserFactory(JwtTokenParserFactory tokenParserFactory) {
    final JwtTokenResolverImpl c = copy();
    c.tokenParserFactory = tokenParserFactory;
    return c;
  }

  /**
   * Setter for scheduler.
   *
   * @param scheduler scheduler
   * @return new instance with applied setting
   */
  public JwtTokenResolverImpl scheduler(Scheduler scheduler) {
    final JwtTokenResolverImpl c = copy();
    c.scheduler = scheduler;
    return c;
  }

  /**
   * Setter for cleanupInterval.
   *
   * @param cleanupInterval cleanupInterval
   * @return new instance with applied setting
   */
  public JwtTokenResolverImpl cleanupInterval(Duration cleanupInterval) {
    final JwtTokenResolverImpl c = copy();
    c.cleanupInterval = cleanupInterval;
    return c;
  }

  @Override
  public Map<String, Object> parseBody(String token) {
    JwtTokenParser tokenParser = tokenParserFactory.newParser(token);
    JwtToken jwtToken = tokenParser.parseToken();
    return jwtToken.body();
  }

  @Override
  public Mono<Map<String, Object>> resolve(String token) {
    return Mono.defer(
        () -> {
          JwtTokenParser tokenParser = tokenParserFactory.newParser(token);
          JwtToken jwtToken = tokenParser.parseToken();

          Map<String, Object> header = jwtToken.header();
          String kid = (String) header.get("kid");
          Objects.requireNonNull(kid, "kid is missing");

          LOGGER.log(Level.DEBUG, "[resolveToken][kid:{0}] Resolving token {1}", kid, mask(token));

          // workaround to remove safely on errors
          AtomicReference<Mono<Key>> computedValueHolder = new AtomicReference<>();

          return findKey(kid, computedValueHolder)
              .map(key -> tokenParser.verifyToken(key).body())
              .doOnError(throwable -> cleanup(kid, computedValueHolder))
              .doOnError(
                  throwable ->
                      LOGGER.log(
                          Level.ERROR,
                          "[resolveToken][kid:{0}][{1}] Exception occurred: {2}",
                          kid,
                          mask(token),
                          throwable.toString()))
              .doOnSuccess(
                  s ->
                      LOGGER.log(
                          Level.DEBUG,
                          "[resolveToken][kid:{0}] Resolved token {1}",
                          kid,
                          mask(token)));
        });
  }

  private Mono<Key> findKey(String kid, AtomicReference<Mono<Key>> computedValueHolder) {
    if (cleanupInterval.isZero()) {
      return Mono.defer(() -> keyProvider.findKey(kid)).cache();
    }

    return keyResolutions.computeIfAbsent(
        kid,
        (kid1) -> {
          Mono<Key> result =
              computedValueHolder.updateAndGet(
                  mono ->
                      Mono.defer(() -> keyProvider.findKey(kid1))
                          .cache()
                          .doOnError(ex -> keyResolutions.remove(kid1)));
          scheduleCleanup(kid, computedValueHolder);
          return result;
        });
  }

  private void scheduleCleanup(String kid, AtomicReference<Mono<Key>> computedValueHolder) {
    scheduler.schedule(
        () -> cleanup(kid, computedValueHolder), cleanupInterval.toMillis(), TimeUnit.MILLISECONDS);
  }

  private void cleanup(String kid, AtomicReference<Mono<Key>> computedValueHolder) {
    if (computedValueHolder.get() != null) {
      keyResolutions.remove(kid, computedValueHolder.get());
    }
  }

  private static String mask(String data) {
    if (data == null || data.isEmpty() || data.length() < 5) {
      return "*****";
    }
    return data.replace(data.substring(2, data.length() - 2), "***");
  }

  private JwtTokenResolverImpl copy() {
    return new JwtTokenResolverImpl(this);
  }
}
