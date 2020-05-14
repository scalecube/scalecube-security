package io.scalecube.security.tokens.jwt;

import java.security.Key;
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

  private final KeyProvider keyProvider;
  private final JwtTokenParserFactory tokenParserFactory;
  private final int cleanupIntervalSec;
  private final Scheduler scheduler;

  private final Map<String, Mono<Key>> keyResolutions = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param keyProvider key provider
   * @param tokenParserFactory token parser factoty
   */
  public JwtTokenResolverImpl(KeyProvider keyProvider, JwtTokenParserFactory tokenParserFactory) {
    this(keyProvider, tokenParserFactory, 3600, Schedulers.newSingle("caching-key-provider", true));
  }

  /**
   * Constructor.
   *
   * @param keyProvider key provider
   * @param tokenParserFactory token parser factoty
   * @param cleanupIntervalSec cleanup interval (in sec) for resolved cached keys
   * @param scheduler cleanup scheduler
   */
  public JwtTokenResolverImpl(
      KeyProvider keyProvider,
      JwtTokenParserFactory tokenParserFactory,
      int cleanupIntervalSec,
      Scheduler scheduler) {
    this.keyProvider = keyProvider;
    this.tokenParserFactory = tokenParserFactory;
    this.cleanupIntervalSec = cleanupIntervalSec;
    this.scheduler = scheduler;
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
                  mono -> Mono.defer(() -> keyProvider.findKey(kid)).cache());
          scheduleCleanup(kid, computedValueHolder);
          return result;
        });
  }

  private void scheduleCleanup(String kid, AtomicReference<Mono<Key>> computedValueHolder) {
    scheduler.schedule(
        () -> cleanup(kid, computedValueHolder), cleanupIntervalSec, TimeUnit.SECONDS);
  }

  private void cleanup(String kid, AtomicReference<Mono<Key>> computedValueHolder) {
    if (computedValueHolder.get() != null) {
      keyResolutions.remove(kid, computedValueHolder.get());
    }
  }
}
