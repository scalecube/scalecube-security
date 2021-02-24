package io.scalecube.security.tokens.jwt;

import io.scalecube.security.tokens.jwt.jsonwebtoken.JsonwebtokenParserFactory;
import java.security.Key;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

public final class JwtTokenResolverImpl implements JwtTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenResolver.class);

  private static final Duration CLEANUP_INTERVAL = Duration.ofSeconds(60);

  private final KeyProvider keyProvider;
  private final JwtTokenParserFactory tokenParserFactory;
  private final Scheduler scheduler;
  private final Duration cleanupInterval;

  private final Map<String, Mono<Key>> keyResolutions = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param keyProvider key provider
   */
  public JwtTokenResolverImpl(KeyProvider keyProvider) {
    this(keyProvider, new JsonwebtokenParserFactory(), newScheduler(), CLEANUP_INTERVAL);
  }

  /**
   * Constructor.
   *
   * @param keyProvider key provider
   * @param tokenParserFactory token parser factoty
   * @param scheduler cleanup scheduler
   * @param cleanupInterval cleanup interval for resolved cached keys
   */
  public JwtTokenResolverImpl(
      KeyProvider keyProvider,
      JwtTokenParserFactory tokenParserFactory,
      Scheduler scheduler,
      Duration cleanupInterval) {
    this.keyProvider = keyProvider;
    this.tokenParserFactory = tokenParserFactory;
    this.scheduler = scheduler;
    this.cleanupInterval = cleanupInterval;
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

          Map<String, Object> body = jwtToken.body();
          String aud = (String) body.get("aud"); // optional

          LOGGER.debug(
              "[resolveToken][aud:{}][kid:{}] Resolving token {}", aud, kid, Utils.mask(token));

          // workaround to remove safely on errors
          AtomicReference<Mono<Key>> computedValueHolder = new AtomicReference<>();

          return findKey(kid, computedValueHolder)
              .map(key -> tokenParser.verifyToken(key).body())
              .doOnError(throwable -> cleanup(kid, computedValueHolder))
              .doOnError(
                  throwable ->
                      LOGGER.error(
                          "[resolveToken][aud:{}][kid:{}][{}] Exception occurred: {}",
                          aud,
                          kid,
                          Utils.mask(token),
                          throwable.toString()))
              .doOnSuccess(
                  s ->
                      LOGGER.debug(
                          "[resolveToken][aud:{}][kid:{}] Resolved token {}",
                          aud,
                          kid,
                          Utils.mask(token)));
        });
  }

  private Mono<Key> findKey(String kid, AtomicReference<Mono<Key>> computedValueHolder) {
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

  private static Scheduler newScheduler() {
    return Schedulers.newElastic("token-resolver-cleaner", 60, true);
  }
}
